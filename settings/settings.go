// Package settings is the tool settings contract: what a scan tool lets an
// administrator configure, declared as a small JSON Schema in the "config"
// of its tool manifest, and the layered values a scan runs with.
//
// The schema language is a closed subset of JSON Schema 2020-12 plus x-octm-*
// annotations. Anything outside the subset makes the schema invalid, so a
// schema cannot hide a field behind $ref, oneOf or a conditional. The
// platform validates what an administrator enters with this package and the
// sensor validates it again before a task uses it; both import the same
// code, so the two can never disagree.
//
// Annotations:
//
//   - x-octm-scope ("sensor" | "scan"): the lowest layer allowed to set the
//     key;
//   - x-octm-tier ("T0" | "T1" | "T2"): the safety class of a non-default
//     value: T0 safe, T1 impact (more load or reach on the target), T2
//     dangerous (intrusive; needs the tenant's explicit enablement and a T2
//     scan);
//   - x-octm-common: the property is one of the common tool options of
//     package tooloption (its type and bounds are checked against it); a
//     property named like a common option must declare it;
//   - x-octm-flag: the tool's native flag the value maps to ("-rate-limit"),
//     shown in the effective configuration of a job; the tool's adapter
//     still builds the argv itself, from typed values;
//   - x-octm-sensitive, x-octm-restart, x-octm-group, x-octm-order,
//     x-octm-widget: presentation and handling.
//
// Layers (Resolve): the tool's defaults, then the sensor's configuration,
// then a scan profile or workflow step, then the scan, then the platform's
// decision for one job. For a common option that narrows down (rate,
// concurrency, retries), a later layer may only lower what an earlier layer
// set; a raise is an error, never silently applied.
//
// The test vectors in testdata/vectors pin the verdicts, error paths,
// defaults and digests.
package settings

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis/tooloption"
)

// Limits of a settings schema.
const (
	// MaxSchemaBytes bounds a schema document.
	MaxSchemaBytes = 32 << 10
	// MaxProperties bounds the properties of a schema, nested ones
	// included.
	MaxProperties = 64
	// MaxEnum bounds an enum.
	MaxEnum = 256
	// MaxPatternLen bounds a pattern's length.
	MaxPatternLen = 512
	// MaxStringLen bounds any string value (a maxLength, when set,
	// may only lower it).
	MaxStringLen = 4096
	// MaxItems bounds any array value (a maxItems, when set, may
	// only lower it).
	MaxItems = 256
)

// Scope is the lowest level allowed to set a key.
type Scope string

// Setting scopes (x-octm-scope).
const (
	// ScopeSensor: only the sensor's own settings may set the key
	// (the default).
	ScopeSensor Scope = "sensor"
	// ScopeScan: the sensor's settings, a scan profile and a scan may
	// set the key.
	ScopeScan Scope = "scan"
)

// Source is where an effective value came from.
type Source string

// Setting sources, from lowest to highest precedence.
const (
	SourceDefault Source = "default"
	// SourceTenant: the tenant's policy for every sensor.
	SourceTenant  Source = "tenant"
	SourceSensor  Source = "sensor"
	SourceProfile Source = "profile"
	SourceScan    Source = "scan"
	// SourceJob: the platform's decision for one job (learned budgets).
	SourceJob Source = "job"
	// SourceLocal: the sensor's local policy, applied last; it only ever
	// lowers a value (its host owner's caps).
	SourceLocal Source = "local"
)

// adminSource reports whether a layer is set by an administrator for the
// sensor (or every sensor), so it may set keys of scope "sensor".
func adminSource(src Source) bool {
	return src == SourceTenant || src == SourceSensor || src == SourceLocal
}

// Setting types.
const (
	settingTypeBoolean = "boolean"
	settingTypeInteger = "integer"
	settingTypeNumber  = "number"
	settingTypeString  = "string"
	settingTypeArray   = "array"
	settingTypeObject  = "object"
)

var (
	settingNameRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	settingFormats = map[string]bool{"hostname": true, "uri": true, "duration": true}
	settingWidgets = map[string]bool{"slider": true, "textarea": true, "tags": true}
	settingTiers   = map[string]bool{"T0": true, "T1": true, "T2": true}
	settingFlagRE  = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9-]{0,47}$`)
	hostnameRE     = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)
)

// Keywords a property may carry (the root additionally allows $schema and
// x-octm-schema-version).
var settingKeywords = map[string]bool{
	"title": true, "description": true, "type": true, "enum": true, "const": true,
	"default": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
	"exclusiveMaximum": true, "multipleOf": true, "minLength": true, "maxLength": true,
	"pattern": true, "format": true, "items": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "properties": true, "required": true, "additionalProperties": true,
	"deprecated": true, "writeOnly": true, "examples": true,
	"x-octm-scope": true, "x-octm-tier": true, "x-octm-sensitive": true, "x-octm-restart": true,
	"x-octm-group": true, "x-octm-order": true, "x-octm-widget": true,
	"x-octm-common": true, "x-octm-flag": true,
}

// ValidName reports whether name is a well-formed setting key name
// (^[a-z][a-z0-9_]{0,63}$).
func ValidName(name string) bool { return settingNameRE.MatchString(name) }

// SchemaError is why a schema is invalid. Path is a JSON pointer
// into the schema document.
type SchemaError struct {
	Path    string
	Message string
}

func (e *SchemaError) Error() string {
	return "settings schema " + e.Path + ": " + e.Message
}

// Error is one invalid value. Path is a JSON pointer into the values
// document ("/rate_limit", "/group/key", "/tags/2").
type Error struct {
	Path    string
	Message string
}

// Errors is every problem of a values document, sorted by path.
type Errors []Error

func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, x := range e {
		parts[i] = x.Path + ": " + x.Message
	}
	return "invalid settings: " + strings.Join(parts, "; ")
}

// Paths returns the error paths.
func (e Errors) Paths() []string {
	out := make([]string, len(e))
	for i, x := range e {
		out[i] = x.Path
	}
	return out
}

// Property is one key of a schema.
type Property struct {
	Name        string
	Title       string
	Description string
	// Type is "boolean", "integer", "number", "string", "array" or
	// "object" (a group of keys, one level deep); empty for a key that only
	// has enum or const.
	Type string
	// Items describes an array's elements.
	Items *Property
	// Properties are a group's keys, sorted by name.
	Properties []*Property
	Required   []string
	Enum       []any
	Const      any
	HasConst   bool
	Default    any
	HasDefault bool

	Minimum, Maximum                   *float64
	ExclusiveMinimum, ExclusiveMaximum *float64
	MultipleOf                         *float64
	MinLength, MaxLength               *int
	MinItems, MaxItems                 *int
	UniqueItems                        bool
	Pattern                            string
	Format                             string

	Deprecated bool
	WriteOnly  bool
	Scope      Scope
	// Tier is the minimum tier whose policy permits a non-default value
	// ("T0", "T1", "T2"); empty: any tier.
	Tier      string
	Sensitive bool
	Restart   bool
	Group     string
	Order     int
	Widget    string
	// Common is the common tool option (package tooloption) the key is,
	// "" for a key specific to the tool. Top-level keys only.
	Common string
	// Flag is the tool's native flag the value maps to ("-rate-limit"):
	// shown in a job's effective configuration, never used to build argv.
	Flag string

	pattern *regexp.Regexp
}

// Schema is a tool's parsed settings schema.
type Schema struct {
	// Raw is the schema document as declared.
	Raw json.RawMessage
	// Version is x-octm-schema-version: it increases when a key is removed
	// or narrowed.
	Version int
	// Title and Description describe the tool's settings.
	Title       string
	Description string
	// Properties are the top-level keys, sorted by name.
	Properties []*Property
	// Required are the keys that must have a value (given or default).
	Required []string

	digest string
}

// ParseSchema parses and checks a schema: the allowed keywords
// only, additionalProperties false on every object, one level of grouping,
// defaults and enums that satisfy their own constraints, RE2 patterns, and
// the size limits.
func ParseSchema(raw []byte) (*Schema, error) {
	if len(raw) > MaxSchemaBytes {
		return nil, &SchemaError{Path: "", Message: fmt.Sprintf("larger than %d bytes", MaxSchemaBytes)}
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	root, err := decodeSettingsJSON(raw)
	if err != nil {
		return nil, &SchemaError{Path: "", Message: "not JSON: " + err.Error()}
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, &SchemaError{Path: "", Message: "not an object"}
	}
	for _, k := range settingKeys(obj) {
		if k == "$schema" || k == "x-octm-schema-version" {
			continue
		}
		if !settingKeywords[k] {
			return nil, &SchemaError{Path: pointer("", k), Message: "keyword not allowed"}
		}
	}
	if s, ok := obj["$schema"]; ok {
		if v, isStr := s.(string); !isStr || v != "https://json-schema.org/draft/2020-12/schema" {
			return nil, &SchemaError{Path: "/$schema", Message: "must be the JSON Schema 2020-12 URI"}
		}
	}
	version, err := intKeyword(obj, "", "x-octm-schema-version")
	if err != nil {
		return nil, err
	}
	if version == nil || *version < 1 {
		return nil, &SchemaError{Path: "/x-octm-schema-version", Message: "required, an integer of at least 1"}
	}
	if t, _ := obj["type"].(string); t != settingTypeObject {
		return nil, &SchemaError{Path: "/type", Message: `the root must be of type "object"`}
	}
	for _, k := range []string{"x-octm-scope", "x-octm-tier", "x-octm-sensitive", "x-octm-restart",
		"x-octm-group", "x-octm-order", "x-octm-widget", "x-octm-common", "x-octm-flag", "enum", "const", "default", "items",
		"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength",
		"maxLength", "pattern", "format", "minItems", "maxItems", "uniqueItems", "writeOnly"} {
		if _, ok := obj[k]; ok {
			return nil, &SchemaError{Path: pointer("", k), Message: "not allowed on the root object"}
		}
	}
	count := 0
	group, err := parseSettingProperty(obj, "", "", 0, &count)
	if err != nil {
		return nil, err
	}
	common := map[string]string{}
	for _, p := range group.Properties {
		if p.Common == "" {
			continue
		}
		if other, dup := common[p.Common]; dup {
			return nil, &SchemaError{Path: pointer(pointer("/properties", p.Name), "x-octm-common"),
				Message: fmt.Sprintf("common option %q is already declared by %q", p.Common, other)}
		}
		common[p.Common] = p.Name
	}
	digest, err := canonicalDigest(root)
	if err != nil {
		return nil, &SchemaError{Path: "", Message: err.Error()}
	}
	return &Schema{
		Raw:         json.RawMessage(slices.Clone(raw)),
		Version:     *version,
		Title:       group.Title,
		Description: group.Description,
		Properties:  group.Properties,
		Required:    group.Required,
		digest:      digest,
	}, nil
}

// MustParseSchema is ParseSchema for a schema compiled into
// the program; it panics on an invalid one (a programming error).
func MustParseSchema(raw string) *Schema {
	s, err := ParseSchema([]byte(raw))
	if err != nil {
		panic(err)
	}
	return s
}

// Digest is "sha256:" + the hex SHA-256 of the schema's canonical JSON
// (object members sorted, no insignificant whitespace, numbers as written,
// no HTML escaping). The manifest carries it; the platform stores schemas by
// it.
func (s *Schema) Digest() string {
	if s == nil {
		return ""
	}
	return s.digest
}

// Property returns a key by its path ("rate_limit", "group.key"), or nil.
func (s *Schema) Property(path string) *Property {
	if s == nil {
		return nil
	}
	name, rest, nested := strings.Cut(path, ".")
	for _, p := range s.Properties {
		if p.Name != name {
			continue
		}
		if !nested {
			return p
		}
		for _, c := range p.Properties {
			if c.Name == rest {
				return c
			}
		}
	}
	return nil
}

// Validate checks a values document: every key known, every value of the
// right type and within its constraints, sensitive keys absent (secrets
// never travel as plain values), and every required key given or
// defaulted. The error is Errors with every problem.
func (s *Schema) Validate(values map[string]any) error {
	if s == nil {
		if len(values) == 0 {
			return nil
		}
		return Errors{{Path: "", Message: "the tool has no settings"}}
	}
	return s.validate(normalizeSettings(values), true)
}

func (s *Schema) validate(values map[string]any, checkRequired bool) error {
	var errs Errors
	validateGroup(s.Properties, s.Required, values, "", checkRequired, &errs)
	if len(errs) == 0 {
		return nil
	}
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Path < errs[j].Path })
	return errs
}

// ValidateJSON is Validate for a JSON object (numbers kept exact).
func (s *Schema) ValidateJSON(raw []byte) error {
	v, err := decodeSettingsJSON(raw)
	if err != nil {
		return Errors{{Path: "", Message: "not JSON: " + err.Error()}}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Errors{{Path: "", Message: "not an object"}}
	}
	return s.Validate(m)
}

// Defaults returns every key that has a default, groups as nested objects.
// The map is the caller's.
func (s *Schema) Defaults() map[string]any {
	out := map[string]any{}
	if s == nil {
		return out
	}
	for _, p := range s.Properties {
		if p.Type == settingTypeObject {
			sub := map[string]any{}
			for _, c := range p.Properties {
				if c.HasDefault {
					sub[c.Name] = cloneSettingValue(c.Default)
				}
			}
			if len(sub) > 0 {
				out[p.Name] = sub
			}
			continue
		}
		if p.HasDefault {
			out[p.Name] = cloneSettingValue(p.Default)
		}
	}
	return out
}

// Layer is one level of values, applied over the ones below it.
type Layer struct {
	Source Source
	Values map[string]any
}

// Resolve computes the effective settings: the defaults, then each layer in
// order (sensor, then profile, then scan). Each layer must be valid on its
// own, and a profile or scan layer may set only keys whose scope is "scan".
// A nil schema gives empty settings (the tool's own defaults).
func (s *Schema) Resolve(layers ...Layer) (*Values, error) {
	ts := &Values{values: map[string]any{}, sources: map[string]Source{}}
	if s == nil {
		for _, l := range layers {
			if len(l.Values) > 0 {
				return nil, Errors{{Path: "", Message: "the tool has no settings"}}
			}
		}
		return ts, nil
	}
	ts.digest, ts.version = s.digest, s.Version
	for k, v := range flattenSettings(s.Defaults()) {
		ts.values[k], ts.sources[k] = v, SourceDefault
	}
	for _, l := range layers {
		switch l.Source {
		case SourceTenant, SourceSensor, SourceProfile, SourceScan, SourceJob, SourceLocal:
		default:
			return nil, fmt.Errorf("settings layer: unknown source %q", l.Source)
		}
		values := normalizeSettings(l.Values)
		if err := s.validate(values, false); err != nil {
			return nil, err
		}
		var errs Errors
		for k, v := range flattenSettings(values) {
			if !adminSource(l.Source) {
				if p := s.Property(k); p == nil || p.Scope != ScopeScan {
					errs = append(errs, Error{Path: "/" + strings.ReplaceAll(k, ".", "/"),
						Message: fmt.Sprintf("may be set only in the sensor's settings, not by a %s", l.Source)})
					continue
				}
			}
			if msg := s.narrowing(k, ts, v, l.Source); msg != "" {
				errs = append(errs, Error{Path: "/" + strings.ReplaceAll(k, ".", "/"), Message: msg})
				continue
			}
			ts.values[k], ts.sources[k] = cloneSettingValue(v), l.Source
		}
		if len(errs) > 0 {
			sort.SliceStable(errs, func(i, j int) bool { return errs[i].Path < errs[j].Path })
			return nil, errs
		}
	}
	var missing Errors
	checkRequiredFlat(s.Properties, s.Required, "", ts.values, &missing)
	if len(missing) > 0 {
		sort.SliceStable(missing, func(i, j int) bool { return missing[i].Path < missing[j].Path })
		return nil, missing
	}
	return ts, nil
}

// narrowing returns why layer src may not set key to v, or "". For a
// common option that narrows down:
//
//   - an administrator's layer (tenant, sensor) may not raise a value an
//     earlier administrator's layer set (a tenant cap binds the sensor);
//     the tool's default is not a cap for them;
//   - every other layer (profile, scan, job, local) may only lower the
//     value in force, the tool's default included: raising a rate or a
//     concurrency is an administrator's decision.
func (s *Schema) narrowing(key string, ts *Values, v any, src Source) string {
	p := s.Property(key)
	if p == nil || p.Common == "" {
		return ""
	}
	cur, set := ts.sources[key]
	if !set || (cur == SourceDefault && (src == SourceTenant || src == SourceSensor)) {
		return ""
	}
	o, _ := tooloption.Lookup(p.Common)
	earlier, ok1 := settingNumber(ts.values[key])
	later, ok2 := settingNumber(v)
	if !ok1 || !ok2 {
		return ""
	}
	if _, ok := o.NarrowValue(earlier, later); !ok {
		if cur == SourceDefault {
			return fmt.Sprintf("may only lower the tool's default (%s); an administrator raises it in the sensor's settings", formatSettingNumber(earlier))
		}
		return fmt.Sprintf("may only lower the value the %s set (%s)", cur, formatSettingNumber(earlier))
	}
	return ""
}

func settingNumber(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func checkRequiredFlat(props []*Property, required []string, prefix string, values map[string]any, errs *Errors) {
	for _, r := range required {
		if _, ok := values[prefix+r]; !ok {
			if p := findProperty(props, r); p != nil && p.Type != settingTypeObject {
				*errs = append(*errs, Error{Path: "/" + strings.ReplaceAll(prefix+r, ".", "/"), Message: "required"})
			}
		}
	}
	for _, p := range props {
		if p.Type == settingTypeObject {
			checkRequiredFlat(p.Properties, p.Required, p.Name+".", values, errs)
		}
	}
}

// Values are a tool's effective settings for one scan. A nil
// *Values has no values: every getter reports false and the tool uses
// its own defaults. Keys of a group are addressed as "group.key".
type Values struct {
	values  map[string]any
	sources map[string]Source
	digest  string
	version int
}

// Int returns an integer value.
func (t *Values) Int(key string) (int64, bool) {
	v, ok := t.get(key)
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		f, ferr := n.Float64()
		if ferr != nil || f != math.Trunc(f) || f > math.MaxInt64 || f < math.MinInt64 {
			return 0, false
		}
		return int64(f), true
	}
	return i, true
}

// Float returns a number (or integer) value.
func (t *Values) Float(key string) (float64, bool) {
	v, ok := t.get(key)
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// Bool returns a boolean value.
func (t *Values) Bool(key string) (bool, bool) {
	v, ok := t.get(key)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// String returns a string value.
func (t *Values) String(key string) (string, bool) {
	v, ok := t.get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Duration returns a string value of format "duration" as a time.Duration.
func (t *Values) Duration(key string) (time.Duration, bool) {
	s, ok := t.String(key)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	return d, err == nil
}

// Strings returns an array of strings (a copy).
func (t *Values) Strings(key string) ([]string, bool) {
	v, ok := t.get(key)
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// Secret returns a sensitive value. Secret settings are not delivered yet,
// so it always reports false; a tool that asks for one keeps working when
// they are.
func (t *Values) Secret(string) ([]byte, bool) { return nil, false }

// Source returns where a key's value came from; empty when it has none.
func (t *Values) Source(key string) Source {
	if t == nil {
		return ""
	}
	return t.sources[key]
}

// Keys returns the keys that have a value, sorted.
func (t *Values) Keys() []string {
	if t == nil {
		return nil
	}
	return settingKeys(t.values)
}

// SchemaDigest and SchemaVersion identify the schema the settings were
// resolved against.
func (t *Values) SchemaDigest() string {
	if t == nil {
		return ""
	}
	return t.digest
}

// SchemaVersion is the schema's x-octm-schema-version.
func (t *Values) SchemaVersion() int {
	if t == nil {
		return 0
	}
	return t.version
}

// Values returns a copy of the effective values by key (numbers as
// json.Number), for a tool that takes its settings as one document (the
// tool contract's task configuration). nil for nil settings.
func (t *Values) Values() map[string]any {
	if t == nil {
		return nil
	}
	out := make(map[string]any, len(t.values))
	for k, v := range t.values {
		out[k] = v
	}
	return out
}

func (t *Values) get(key string) (any, bool) {
	if t == nil {
		return nil, false
	}
	v, ok := t.values[key]
	return v, ok
}

// --- parsing ---------------------------------------------------------------

func parseSettingProperty(obj map[string]any, path, name string, depth int, count *int) (*Property, error) {
	p := &Property{Name: name, Scope: ScopeSensor}
	for _, k := range settingKeys(obj) {
		if depth > 0 && !settingKeywords[k] {
			if strings.HasPrefix(k, "x-octm-") {
				return nil, &SchemaError{Path: pointer(path, k), Message: "unknown annotation"}
			}
			return nil, &SchemaError{Path: pointer(path, k), Message: "keyword not allowed"}
		}
	}
	var err error
	if p.Title, err = strKeyword(obj, path, "title"); err != nil {
		return nil, err
	}
	if p.Description, err = strKeyword(obj, path, "description"); err != nil {
		return nil, err
	}
	if p.Type, err = strKeyword(obj, path, "type"); err != nil {
		return nil, err
	}
	switch p.Type {
	case "", settingTypeBoolean, settingTypeInteger, settingTypeNumber, settingTypeString, settingTypeArray:
	case settingTypeObject:
		if depth > 1 {
			return nil, &SchemaError{Path: pointer(path, "type"), Message: "groups may not be nested"}
		}
	default:
		return nil, &SchemaError{Path: pointer(path, "type"), Message: fmt.Sprintf("type %q not allowed", p.Type)}
	}
	if p.Deprecated, err = boolKeyword(obj, path, "deprecated"); err != nil {
		return nil, err
	}
	if p.WriteOnly, err = boolKeyword(obj, path, "writeOnly"); err != nil {
		return nil, err
	}
	if p.Sensitive, err = boolKeyword(obj, path, "x-octm-sensitive"); err != nil {
		return nil, err
	}
	if p.Restart, err = boolKeyword(obj, path, "x-octm-restart"); err != nil {
		return nil, err
	}
	if p.Sensitive {
		p.WriteOnly = true
	}
	if scope, err := strKeyword(obj, path, "x-octm-scope"); err != nil {
		return nil, err
	} else if scope != "" {
		switch Scope(scope) {
		case ScopeSensor, ScopeScan:
			p.Scope = Scope(scope)
		default:
			return nil, &SchemaError{Path: pointer(path, "x-octm-scope"), Message: `must be "sensor" or "scan"`}
		}
	}
	if p.Tier, err = strKeyword(obj, path, "x-octm-tier"); err != nil {
		return nil, err
	}
	if p.Tier != "" && !settingTiers[p.Tier] {
		return nil, &SchemaError{Path: pointer(path, "x-octm-tier"), Message: `must be "T0", "T1" or "T2"`}
	}
	if p.Group, err = strKeyword(obj, path, "x-octm-group"); err != nil {
		return nil, err
	}
	if order, err := intKeyword(obj, path, "x-octm-order"); err != nil {
		return nil, err
	} else if order != nil {
		p.Order = *order
	}
	if p.Widget, err = strKeyword(obj, path, "x-octm-widget"); err != nil {
		return nil, err
	}
	if p.Widget != "" && !settingWidgets[p.Widget] {
		return nil, &SchemaError{Path: pointer(path, "x-octm-widget"), Message: "unknown widget"}
	}
	if p.Common, err = strKeyword(obj, path, "x-octm-common"); err != nil {
		return nil, err
	}
	if p.Common != "" {
		if depth != 1 || name == "" {
			return nil, &SchemaError{Path: pointer(path, "x-octm-common"), Message: "allowed only on a top-level key"}
		}
		if _, ok := tooloption.Lookup(p.Common); !ok {
			return nil, &SchemaError{Path: pointer(path, "x-octm-common"), Message: fmt.Sprintf("%q is not a common tool option", p.Common)}
		}
	}
	if depth == 1 && name != "" {
		if why, ok := tooloption.Reserved(name); ok {
			return nil, &SchemaError{Path: path, Message: "reserved name: " + why}
		}
	}
	if p.Flag, err = strKeyword(obj, path, "x-octm-flag"); err != nil {
		return nil, err
	}
	if p.Flag != "" && !settingFlagRE.MatchString(p.Flag) {
		return nil, &SchemaError{Path: pointer(path, "x-octm-flag"), Message: "must be one command-line flag such as -rate-limit"}
	}
	if ex, ok := obj["examples"]; ok {
		if _, isArr := ex.([]any); !isArr {
			return nil, &SchemaError{Path: pointer(path, "examples"), Message: "must be an array"}
		}
	}

	if p.Type == settingTypeObject {
		return parseSettingGroup(p, obj, path, depth, count)
	}
	for _, k := range []string{"properties", "required", "additionalProperties"} {
		if _, ok := obj[k]; ok {
			return nil, &SchemaError{Path: pointer(path, k), Message: "allowed only on an object"}
		}
	}
	if err := parseSettingConstraints(p, obj, path, depth, count); err != nil {
		return nil, err
	}
	if p.Common != "" {
		o, _ := tooloption.Lookup(p.Common)
		if err := o.CheckProperty(p.Type, p.Minimum, p.Maximum); err != nil {
			return nil, &SchemaError{Path: pointer(path, "x-octm-common"), Message: err.Error()}
		}
		if p.ExclusiveMinimum != nil || p.ExclusiveMaximum != nil {
			return nil, &SchemaError{Path: pointer(path, "x-octm-common"), Message: "a common option takes minimum and maximum, not exclusive bounds"}
		}
		// Unbounded sides take the common bounds, so values are checked
		// against them.
		if p.Minimum == nil {
			v := float64(o.Minimum)
			p.Minimum = &v
		}
		if p.Maximum == nil {
			v := float64(o.Maximum)
			p.Maximum = &v
		}
	}
	return p, nil
}

func parseSettingGroup(p *Property, obj map[string]any, path string, depth int, count *int) (*Property, error) {
	for _, k := range []string{"enum", "const", "default", "items", "minimum", "maximum", "exclusiveMinimum",
		"exclusiveMaximum", "multipleOf", "minLength", "maxLength", "pattern", "format", "minItems",
		"maxItems", "uniqueItems"} {
		if _, ok := obj[k]; ok {
			return nil, &SchemaError{Path: pointer(path, k), Message: "not allowed on an object"}
		}
	}
	ap, ok := obj["additionalProperties"]
	if b, isBool := ap.(bool); !ok || !isBool || b {
		return nil, &SchemaError{Path: pointer(path, "additionalProperties"), Message: "must be false"}
	}
	rawProps, ok := obj["properties"]
	if !ok {
		return nil, &SchemaError{Path: pointer(path, "properties"), Message: "required on an object"}
	}
	props, ok := rawProps.(map[string]any)
	if !ok {
		return nil, &SchemaError{Path: pointer(path, "properties"), Message: "must be an object"}
	}
	for _, name := range settingKeys(props) {
		ppath := pointer(pointer(path, "properties"), name)
		if !settingNameRE.MatchString(name) {
			return nil, &SchemaError{Path: ppath, Message: "key names are lowercase letters, digits and '_', starting with a letter, at most 64"}
		}
		*count++
		if *count > MaxProperties {
			return nil, &SchemaError{Path: ppath, Message: fmt.Sprintf("more than %d properties", MaxProperties)}
		}
		sub, ok := props[name].(map[string]any)
		if !ok {
			return nil, &SchemaError{Path: ppath, Message: "must be an object"}
		}
		child, err := parseSettingProperty(sub, ppath, name, depth+1, count)
		if err != nil {
			return nil, err
		}
		if child.Type == settingTypeObject && depth > 0 {
			return nil, &SchemaError{Path: pointer(ppath, "type"), Message: "groups may not be nested"}
		}
		p.Properties = append(p.Properties, child)
	}
	if rawReq, ok := obj["required"]; ok {
		arr, isArr := rawReq.([]any)
		if !isArr {
			return nil, &SchemaError{Path: pointer(path, "required"), Message: "must be an array of key names"}
		}
		for i, r := range arr {
			name, isStr := r.(string)
			if !isStr || !slices.ContainsFunc(p.Properties, func(c *Property) bool { return c.Name == name }) {
				return nil, &SchemaError{Path: pointer(pointer(path, "required"), strconv.Itoa(i)), Message: "not a property"}
			}
			if slices.Contains(p.Required, name) {
				return nil, &SchemaError{Path: pointer(pointer(path, "required"), strconv.Itoa(i)), Message: "listed twice"}
			}
			p.Required = append(p.Required, name)
		}
	}
	return p, nil
}

func parseSettingConstraints(p *Property, obj map[string]any, path string, depth int, count *int) error {
	if err := parseSettingItems(p, obj, path, depth, count); err != nil {
		return err
	}
	if err := checkSettingKeywordPlacement(p, obj, path); err != nil {
		return err
	}
	if err := parseSettingBounds(p, obj, path); err != nil {
		return err
	}
	if err := parseSettingStringRules(p, obj, path); err != nil {
		return err
	}
	// Enum, const and default last: they are checked against the key's
	// own constraints.
	return parseSettingValues(p, obj, path)
}

func parseSettingItems(p *Property, obj map[string]any, path string, depth int, count *int) error {
	if p.Type == settingTypeArray {
		rawItems, ok := obj["items"]
		if !ok {
			return &SchemaError{Path: pointer(path, "items"), Message: "required on an array"}
		}
		sub, ok := rawItems.(map[string]any)
		if !ok {
			return &SchemaError{Path: pointer(path, "items"), Message: "must be an object"}
		}
		ipath := pointer(path, "items")
		for _, k := range []string{"default", "items", "x-octm-scope", "x-octm-tier", "x-octm-sensitive",
			"x-octm-restart", "x-octm-group", "x-octm-order", "x-octm-widget", "deprecated", "writeOnly",
			"minItems", "maxItems", "uniqueItems"} {
			if _, ok := sub[k]; ok {
				return &SchemaError{Path: pointer(ipath, k), Message: "not allowed on array items"}
			}
		}
		item, err := parseSettingProperty(sub, ipath, "", depth+1, count)
		if err != nil {
			return err
		}
		if item.Type == settingTypeArray || item.Type == settingTypeObject {
			return &SchemaError{Path: pointer(ipath, "type"), Message: "array items are scalars"}
		}
		p.Items = item
	} else if _, ok := obj["items"]; ok {
		return &SchemaError{Path: pointer(path, "items"), Message: "allowed only on an array"}
	}

	return nil
}

func checkSettingKeywordPlacement(p *Property, obj map[string]any, path string) error {
	numeric := p.Type == settingTypeInteger || p.Type == settingTypeNumber
	for _, k := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"} {
		if _, ok := obj[k]; ok && !numeric {
			return &SchemaError{Path: pointer(path, k), Message: "allowed only on an integer or number"}
		}
	}
	for _, k := range []string{"minLength", "maxLength", "pattern", "format"} {
		if _, ok := obj[k]; ok && p.Type != settingTypeString {
			return &SchemaError{Path: pointer(path, k), Message: "allowed only on a string"}
		}
	}
	for _, k := range []string{"minItems", "maxItems", "uniqueItems"} {
		if _, ok := obj[k]; ok && p.Type != settingTypeArray {
			return &SchemaError{Path: pointer(path, k), Message: "allowed only on an array"}
		}
	}
	return nil
}

func parseSettingBounds(p *Property, obj map[string]any, path string) error {
	var err error
	if p.Minimum, err = numKeyword(obj, path, "minimum"); err != nil {
		return err
	}
	if p.Maximum, err = numKeyword(obj, path, "maximum"); err != nil {
		return err
	}
	if p.ExclusiveMinimum, err = numKeyword(obj, path, "exclusiveMinimum"); err != nil {
		return err
	}
	if p.ExclusiveMaximum, err = numKeyword(obj, path, "exclusiveMaximum"); err != nil {
		return err
	}
	if p.MultipleOf, err = numKeyword(obj, path, "multipleOf"); err != nil {
		return err
	}
	if p.MultipleOf != nil && *p.MultipleOf <= 0 {
		return &SchemaError{Path: pointer(path, "multipleOf"), Message: "must be greater than 0"}
	}
	if p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum {
		return &SchemaError{Path: pointer(path, "minimum"), Message: "greater than maximum"}
	}
	if p.MinLength, err = intKeyword(obj, path, "minLength"); err != nil {
		return err
	}
	if p.MaxLength, err = intKeyword(obj, path, "maxLength"); err != nil {
		return err
	}
	if p.MinItems, err = intKeyword(obj, path, "minItems"); err != nil {
		return err
	}
	if p.MaxItems, err = intKeyword(obj, path, "maxItems"); err != nil {
		return err
	}
	for _, c := range []struct {
		k   string
		v   *int
		max int
	}{{"minLength", p.MinLength, MaxStringLen}, {"maxLength", p.MaxLength, MaxStringLen},
		{"minItems", p.MinItems, MaxItems}, {"maxItems", p.MaxItems, MaxItems}} {
		if c.v != nil && (*c.v < 0 || *c.v > c.max) {
			return &SchemaError{Path: pointer(path, c.k), Message: fmt.Sprintf("must be between 0 and %d", c.max)}
		}
	}
	if p.MinLength != nil && p.MaxLength != nil && *p.MinLength > *p.MaxLength {
		return &SchemaError{Path: pointer(path, "minLength"), Message: "greater than maxLength"}
	}
	if p.MinItems != nil && p.MaxItems != nil && *p.MinItems > *p.MaxItems {
		return &SchemaError{Path: pointer(path, "minItems"), Message: "greater than maxItems"}
	}
	if p.UniqueItems, err = boolKeyword(obj, path, "uniqueItems"); err != nil {
		return err
	}
	return nil
}

func parseSettingStringRules(p *Property, obj map[string]any, path string) error {
	var err error
	if p.Pattern, err = strKeyword(obj, path, "pattern"); err != nil {
		return err
	}
	if p.Pattern != "" {
		if len(p.Pattern) > MaxPatternLen {
			return &SchemaError{Path: pointer(path, "pattern"), Message: fmt.Sprintf("longer than %d", MaxPatternLen)}
		}
		re, rerr := regexp.Compile(p.Pattern)
		if rerr != nil {
			return &SchemaError{Path: pointer(path, "pattern"), Message: "not an RE2 expression: " + rerr.Error()}
		}
		p.pattern = re
	}
	if p.Format, err = strKeyword(obj, path, "format"); err != nil {
		return err
	}
	if p.Format != "" && !settingFormats[p.Format] {
		return &SchemaError{Path: pointer(path, "format"), Message: `must be "hostname", "uri" or "duration"`}
	}

	return nil
}

func parseSettingValues(p *Property, obj map[string]any, path string) error {
	if rawEnum, ok := obj["enum"]; ok {
		arr, isArr := rawEnum.([]any)
		if !isArr || len(arr) == 0 || len(arr) > MaxEnum {
			return &SchemaError{Path: pointer(path, "enum"), Message: fmt.Sprintf("must be an array of 1 to %d values", MaxEnum)}
		}
		for i, e := range arr {
			epath := pointer(pointer(path, "enum"), strconv.Itoa(i))
			if !isScalar(e) {
				return &SchemaError{Path: epath, Message: "enum values are scalars"}
			}
			for _, prev := range arr[:i] {
				if settingValuesEqual(prev, e) {
					return &SchemaError{Path: epath, Message: "listed twice"}
				}
			}
			var errs Errors
			validateScalar(&Property{Type: p.Type, Format: p.Format, pattern: p.pattern, Pattern: p.Pattern,
				Minimum: p.Minimum, Maximum: p.Maximum, ExclusiveMinimum: p.ExclusiveMinimum,
				ExclusiveMaximum: p.ExclusiveMaximum, MultipleOf: p.MultipleOf, MinLength: p.MinLength,
				MaxLength: p.MaxLength}, e, "", &errs)
			if len(errs) > 0 {
				return &SchemaError{Path: epath, Message: "does not satisfy the key's own constraints: " + errs[0].Message}
			}
		}
		p.Enum = arr
	}
	if c, ok := obj["const"]; ok {
		if !isScalar(c) {
			return &SchemaError{Path: pointer(path, "const"), Message: "must be a scalar"}
		}
		p.Const, p.HasConst = c, true
	}
	if p.Type == "" && p.Enum == nil && !p.HasConst {
		return &SchemaError{Path: pointer(path, "type"), Message: "required unless enum or const is given"}
	}
	if d, ok := obj["default"]; ok {
		if p.Sensitive {
			return &SchemaError{Path: pointer(path, "default"), Message: "a sensitive key has no default"}
		}
		var errs Errors
		validateValue(p, d, "", &errs)
		if len(errs) > 0 {
			return &SchemaError{Path: pointer(path, "default"), Message: "does not satisfy the key's own constraints: " + errs[0].Message}
		}
		p.Default, p.HasDefault = d, true
	}
	return nil
}

// --- validation ------------------------------------------------------------

func validateGroup(props []*Property, required []string, values map[string]any, path string, checkRequired bool, errs *Errors) {
	for _, k := range settingKeys(values) {
		p := findProperty(props, k)
		if p == nil {
			*errs = append(*errs, Error{Path: pointer(path, k), Message: "unknown key"})
			continue
		}
		if p.Sensitive {
			*errs = append(*errs, Error{Path: pointer(path, k), Message: "a sensitive key is not set as a plain value"})
			continue
		}
		if p.Type == settingTypeObject {
			sub, ok := values[k].(map[string]any)
			if !ok {
				*errs = append(*errs, Error{Path: pointer(path, k), Message: "must be an object"})
				continue
			}
			validateGroup(p.Properties, p.Required, sub, pointer(path, k), checkRequired, errs)
			continue
		}
		validateValue(p, values[k], pointer(path, k), errs)
	}
	if !checkRequired {
		return
	}
	for _, p := range props {
		if _, given := values[p.Name]; !given && p.Type == settingTypeObject {
			validateGroup(p.Properties, p.Required, map[string]any{}, pointer(path, p.Name), true, errs)
		}
	}
	for _, r := range required {
		if _, ok := values[r]; ok {
			continue
		}
		if p := findProperty(props, r); p != nil && (p.HasDefault || p.Type == settingTypeObject) {
			continue
		}
		*errs = append(*errs, Error{Path: pointer(path, r), Message: "required"})
	}
}

func validateValue(p *Property, v any, path string, errs *Errors) {
	if p.Type != settingTypeArray {
		validateScalar(p, v, path, errs)
		return
	}
	arr, ok := v.([]any)
	if !ok {
		*errs = append(*errs, Error{Path: path, Message: "must be an array"})
		return
	}
	if len(arr) > MaxItems {
		*errs = append(*errs, Error{Path: path, Message: fmt.Sprintf("more than %d items", MaxItems)})
		return
	}
	if p.MinItems != nil && len(arr) < *p.MinItems {
		*errs = append(*errs, Error{Path: path, Message: fmt.Sprintf("fewer than %d items", *p.MinItems)})
	}
	if p.MaxItems != nil && len(arr) > *p.MaxItems {
		*errs = append(*errs, Error{Path: path, Message: fmt.Sprintf("more than %d items", *p.MaxItems)})
	}
	for i, e := range arr {
		validateScalar(p.Items, e, pointer(path, strconv.Itoa(i)), errs)
		if p.UniqueItems {
			for _, prev := range arr[:i] {
				if settingValuesEqual(prev, e) {
					*errs = append(*errs, Error{Path: pointer(path, strconv.Itoa(i)), Message: "duplicate item"})
					break
				}
			}
		}
	}
	if p.HasConst && !settingValuesEqual(p.Const, v) {
		*errs = append(*errs, Error{Path: path, Message: "must equal the constant"})
	}
}

func validateScalar(p *Property, v any, path string, errs *Errors) {
	add := func(msg string) { *errs = append(*errs, Error{Path: path, Message: msg}) }
	if !isScalar(v) {
		add("must be a scalar")
		return
	}
	switch p.Type {
	case settingTypeBoolean:
		if _, ok := v.(bool); !ok {
			add("must be a boolean")
			return
		}
	case settingTypeInteger, settingTypeNumber:
		n, ok := v.(json.Number)
		if !ok {
			if p.Type == settingTypeInteger {
				add("must be an integer")
			} else {
				add("must be a number")
			}
			return
		}
		f, err := n.Float64()
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			add("not a finite number")
			return
		}
		if p.Type == settingTypeInteger && (f != math.Trunc(f) || math.Abs(f) > 1<<53) {
			add("must be an integer")
			return
		}
		if p.Minimum != nil && f < *p.Minimum {
			add(fmt.Sprintf("less than %s", formatSettingNumber(*p.Minimum)))
		}
		if p.Maximum != nil && f > *p.Maximum {
			add(fmt.Sprintf("greater than %s", formatSettingNumber(*p.Maximum)))
		}
		if p.ExclusiveMinimum != nil && f <= *p.ExclusiveMinimum {
			add(fmt.Sprintf("not greater than %s", formatSettingNumber(*p.ExclusiveMinimum)))
		}
		if p.ExclusiveMaximum != nil && f >= *p.ExclusiveMaximum {
			add(fmt.Sprintf("not less than %s", formatSettingNumber(*p.ExclusiveMaximum)))
		}
		if p.MultipleOf != nil {
			q := f / *p.MultipleOf
			if math.Abs(q-math.Round(q)) > 1e-9 {
				add(fmt.Sprintf("not a multiple of %s", formatSettingNumber(*p.MultipleOf)))
			}
		}
	case settingTypeString:
		s, ok := v.(string)
		if !ok {
			add("must be a string")
			return
		}
		n := len([]rune(s))
		if len(s) > MaxStringLen*4 || n > MaxStringLen {
			add(fmt.Sprintf("longer than %d characters", MaxStringLen))
			return
		}
		if p.MinLength != nil && n < *p.MinLength {
			add(fmt.Sprintf("shorter than %d characters", *p.MinLength))
		}
		if p.MaxLength != nil && n > *p.MaxLength {
			add(fmt.Sprintf("longer than %d characters", *p.MaxLength))
		}
		if p.pattern != nil && !p.pattern.MatchString(s) {
			add("does not match the pattern")
		}
		if p.Format != "" && !validFormat(p.Format, s) {
			add("not a valid " + p.Format)
		}
	}
	if p.Enum != nil && !slices.ContainsFunc(p.Enum, func(e any) bool { return settingValuesEqual(e, v) }) {
		add("not one of the allowed values")
	}
	if p.HasConst && !settingValuesEqual(p.Const, v) {
		add("must equal the constant")
	}
}

func validFormat(format, s string) bool {
	switch format {
	case "hostname":
		return len(s) <= 253 && hostnameRE.MatchString(s)
	case "uri":
		scheme, rest, ok := strings.Cut(s, "://")
		if !ok || rest == "" || strings.ContainsAny(s, " \t\r\n") {
			return false
		}
		return scheme == "http" || scheme == "https"
	case "duration":
		d, err := time.ParseDuration(s)
		return err == nil && d >= 0
	}
	return false
}

// --- helpers ---------------------------------------------------------------

// decodeSettingsJSON decodes one JSON value with exact numbers and refuses
// trailing data.
func decodeSettingsJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// checkNoDuplicateKeys refuses an object with a member listed twice: a
// decoder keeps the last, so a reviewer and a validator could read
// different schemas.
func checkNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		obj  bool
		keys map[string]bool
		path string
		idx  int
		key  string
	}
	var stack []*frame
	child := func() string {
		if len(stack) == 0 {
			return ""
		}
		f := stack[len(stack)-1]
		if f.obj {
			return pointer(f.path, f.key)
		}
		p := pointer(f.path, strconv.Itoa(f.idx))
		f.idx++
		return p
	}
	expectKey := func() bool {
		return len(stack) > 0 && stack[len(stack)-1].obj && stack[len(stack)-1].key == ""
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return &SchemaError{Path: "", Message: "not JSON: " + err.Error()}
		}
		if expectKey() {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].key = ""
				}
				continue
			}
			k, _ := tok.(string)
			f := stack[len(stack)-1]
			if f.keys[k] {
				return &SchemaError{Path: pointer(f.path, k), Message: "member listed twice"}
			}
			f.keys[k] = true
			f.key = k
			continue
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, path: child()})
			case '[':
				stack = append(stack, &frame{path: child()})
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].key = ""
				}
			}
		default:
			if len(stack) > 0 {
				f := stack[len(stack)-1]
				if f.obj {
					f.key = ""
				} else {
					f.idx++
				}
			}
		}
	}
}

// canonicalDigest is "sha256:" + hex SHA-256 of v's canonical JSON: object
// members sorted by key, no insignificant whitespace, numbers exactly as
// written, no HTML escaping (Go's encoding of the decoded value).
func canonicalDigest(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// DocumentDigest is the canonical digest of any JSON document (a values
// document, a settings document): "sha256:" + hex SHA-256 of its canonical
// JSON, as for Schema.Digest.
func DocumentDigest(raw []byte) (string, error) {
	v, err := decodeSettingsJSON(raw)
	if err != nil {
		return "", err
	}
	return canonicalDigest(v)
}

func pointer(base, token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	token = strings.ReplaceAll(token, "/", "~1")
	return base + "/" + token
}

func settingKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func findProperty(props []*Property, name string) *Property {
	for _, p := range props {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func isScalar(v any) bool {
	switch v.(type) {
	case bool, string, json.Number:
		return true
	}
	return false
}

// settingValuesEqual compares scalars (numbers by value) and arrays of them.
func settingValuesEqual(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		fx, ex := x.Float64()
		fy, ey := y.Float64()
		return ex == nil && ey == nil && fx == fy
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !settingValuesEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func cloneSettingValue(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = cloneSettingValue(x[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneSettingValue(e)
		}
		return out
	}
	return v
}

// normalizeSettings returns a copy of values with Go numbers turned into
// json.Number and []string into []any, the form the validator reads.
func normalizeSettings(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for k, v := range values {
		out[k] = normalizeSettingValue(v)
	}
	return out
}

func normalizeSettingValue(v any) any {
	switch x := v.(type) {
	case int:
		return json.Number(strconv.FormatInt(int64(x), 10))
	case int32:
		return json.Number(strconv.FormatInt(int64(x), 10))
	case int64:
		return json.Number(strconv.FormatInt(x, 10))
	case uint:
		return json.Number(strconv.FormatUint(uint64(x), 10))
	case uint32:
		return json.Number(strconv.FormatUint(uint64(x), 10))
	case uint64:
		return json.Number(strconv.FormatUint(x, 10))
	case float32:
		return json.Number(strconv.FormatFloat(float64(x), 'g', -1, 32))
	case float64:
		return json.Number(strconv.FormatFloat(x, 'g', -1, 64))
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalizeSettingValue(x[i])
		}
		return out
	case map[string]any:
		return normalizeSettings(x)
	}
	return v
}

// flattenSettings turns {"group": {"key": v}} into {"group.key": v}.
func flattenSettings(values map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range values {
		if sub, ok := v.(map[string]any); ok {
			for sk, sv := range sub {
				out[k+"."+sk] = sv
			}
			continue
		}
		out[k] = v
	}
	return out
}

func formatSettingNumber(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func strKeyword(obj map[string]any, path, k string) (string, error) {
	v, ok := obj[k]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", &SchemaError{Path: pointer(path, k), Message: "must be a string"}
	}
	return s, nil
}

func boolKeyword(obj map[string]any, path, k string) (bool, error) {
	v, ok := obj[k]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, &SchemaError{Path: pointer(path, k), Message: "must be a boolean"}
	}
	return b, nil
}

func numKeyword(obj map[string]any, path, k string) (*float64, error) {
	v, ok := obj[k]
	if !ok {
		return nil, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil, &SchemaError{Path: pointer(path, k), Message: "must be a number"}
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, &SchemaError{Path: pointer(path, k), Message: "must be a finite number"}
	}
	return &f, nil
}

func intKeyword(obj map[string]any, path, k string) (*int, error) {
	v, ok := obj[k]
	if !ok {
		return nil, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil, &SchemaError{Path: pointer(path, k), Message: "must be an integer"}
	}
	i, err := n.Int64()
	if err != nil || i < math.MinInt32 || i > math.MaxInt32 {
		return nil, &SchemaError{Path: pointer(path, k), Message: "must be an integer"}
	}
	x := int(i)
	return &x, nil
}
