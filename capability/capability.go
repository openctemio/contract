// Package capability is the OpenCTEM capability taxonomy: the closed,
// versioned list of acts a scan tool can perform ("scan.ports@1",
// "probe.http@1", ...), and the contract every implementation of an act
// honors.
//
// A capability, not a tool, carries the facts about the act:
//
//   - its phase (passive or active discovery, assessment, validation,
//     collection) and so its CTEM stage;
//   - its tier floor: how intrusive the act is at minimum. The platform
//     assigns a tool's effective tier as the maximum of the floor, the tool's
//     own request and the platform's classification; a tool can raise its
//     tier, never lower it;
//   - its typed input and output ports and the CTIS asset types each port
//     carries;
//   - its standard params, which every implementation maps to its own config;
//   - the CTIS paths every report of the act must carry;
//   - the MITRE ATT&CK techniques an adversary uses for the same act, the
//     D3FEND defensive functions it performs and CAPEC attack patterns.
//
// A tool declares which capabilities it implements; it cannot invent a
// capability or redefine one. The taxonomy is data (taxonomy.json, embedded)
// so the platform, the SDK and the sensor read one copy.
//
// Versioning: a capability id carries a major version ("scan.ports@1"). A
// minor change (an optional param or output path) keeps the major; changing
// a port, removing or retyping a param or adding a required path is a new
// major, and both majors may be served at once.
//
// Design: OpenCTEM RFC "Tool Contract v1".
package capability

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

//go:embed taxonomy.json
var taxonomyJSON []byte

// Version is the taxonomy format version.
const Version = 1

// Phase is the engagement phase of a capability.
type Phase string

// The closed set of phases.
const (
	PhaseDiscoverPassive Phase = "discover.passive"
	PhaseDiscoverActive  Phase = "discover.active"
	PhaseAssess          Phase = "assess"
	PhaseValidate        Phase = "validate"
	PhaseCollect         Phase = "collect"
)

// PhaseInfo describes one phase.
type PhaseInfo struct {
	ID          Phase  `json:"id"`
	Label       string `json:"label"`
	CTEMStage   string `json:"ctem_stage"`
	Description string `json:"description"`
}

// PortType is the type of a capability port. The set is closed; two ports
// connect only when their types are equal.
type PortType string

// The closed set of port types.
const (
	PortRootDomain     PortType = "root_domain"
	PortHostname       PortType = "hostname"
	PortIP             PortType = "ip"
	PortCIDR           PortType = "cidr"
	PortService        PortType = "service"
	PortURL            PortType = "url"
	PortRepository     PortType = "repository"
	PortContainerImage PortType = "container_image"
	PortCloudAccount   PortType = "cloud_account"
	// PortFinding is an output sink, and an input only for capabilities that
	// act on findings (verify.finding).
	PortFinding PortType = "finding"
)

// PortTypeInfo describes one port type.
type PortTypeInfo struct {
	Type  PortType `json:"type"`
	Label string   `json:"label"`
	// Carries are the CTIS asset types a stream of this type holds; empty
	// for findings.
	Carries []string `json:"carries"`
}

// ParamType is the value type of a standard param.
type ParamType string

// The closed set of param types.
const (
	ParamString     ParamType = "string"
	ParamStringList ParamType = "string_list"
	ParamInteger    ParamType = "integer"
	ParamBoolean    ParamType = "boolean"
	// ParamPortList is a list of ports and port ranges ("80,443,8000-8100").
	ParamPortList ParamType = "port_list"
)

// Param is one standard param of a capability.
type Param struct {
	Name        string    `json:"name"`
	Type        ParamType `json:"type"`
	Description string    `json:"description"`
	// Enum, when set, is the closed set of allowed values (for a list, of
	// each item).
	Enum []string `json:"enum,omitempty"`
	Min  *int     `json:"min,omitempty"`
	Max  *int     `json:"max,omitempty"`
}

// Status is how far a capability is from being runnable.
type Status string

// Statuses.
const (
	// StatusRouted: at least one built-in tool implements it.
	StatusRouted Status = "routed"
	// StatusPlanned: the contract is defined; no built-in implements it yet.
	StatusPlanned Status = "planned"
	// StatusLater: listed so the vocabulary is complete; not runnable, and
	// the contract may still change before the first implementation.
	StatusLater Status = "later"
)

// Deprecation marks a capability major that is being replaced.
type Deprecation struct {
	Since      string `json:"since"`
	ReplacedBy string `json:"replaced_by,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Capability is one entry of the taxonomy at one major version.
type Capability struct {
	ID          string `json:"id"`
	Major       int    `json:"major"`
	Status      Status `json:"status"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Phase       Phase  `json:"phase"`
	// TierFloor is the minimum intrusiveness tier of the act: 0 passive,
	// 1 active non-intrusive, 2 intrusive.
	TierFloor int        `json:"tier_floor"`
	InPorts   []PortType `json:"in_ports"`
	OutPorts  []PortType `json:"out_ports"`
	// ExtraOutputs are output kinds that ride along without being a port
	// ("asset:certificate", "dependency"); "asset:*" allows any asset type.
	ExtraOutputs []string `json:"extra_outputs,omitempty"`
	// FindingTypes, when set, are the only CTIS finding types a report may
	// carry; empty means any.
	FindingTypes []string `json:"finding_types,omitempty"`
	Params       []Param  `json:"params"`
	// Outputs are the required-output rules (see Rule).
	Outputs []Rule   `json:"outputs"`
	ATTACK  []string `json:"attack,omitempty"`
	D3FEND  []string `json:"d3fend,omitempty"`
	CAPEC   []string `json:"capec,omitempty"`
	// CrossCutting capabilities are used by other flows (retests, imports),
	// never as a workflow node.
	CrossCutting bool         `json:"cross_cutting,omitempty"`
	Deprecated   *Deprecation `json:"deprecated,omitempty"`
}

// Rule is a required-output rule: every record of a report that Select
// picks must carry every path in Paths and at least one path in AnyOf. A
// path is present when it holds a value other than null, "" or an empty
// list or object. A rule picking no record is satisfied (an empty result is
// a valid result).
//
// Select is "assets", "findings" or "dependencies", optionally with a type
// filter: "assets[type=open_port]", "assets[type=ip_address|host]",
// "findings[type=secret]". A path is dotted JSON member names relative to
// the record; "[]" after a member means the member is a list that must not
// be empty and the rest of the path applies to every element
// ("technical.domain.dns_records[].type").
//
// Shape names one of several accepted output shapes of a capability. A tool
// that declares its shape is checked against the rules of that shape and the
// unnamed rules only.
type Rule struct {
	Shape  string   `json:"shape,omitempty"`
	Select string   `json:"select"`
	Paths  []string `json:"paths,omitempty"`
	AnyOf  []string `json:"any_of,omitempty"`
}

// Ref is the versioned id, "scan.ports@1".
func (c Capability) Ref() string { return c.ID + "@" + strconv.Itoa(c.Major) }

// CTEMStage is the CTEM stage of the capability's phase.
func (c Capability) CTEMStage() string {
	if p, ok := LookupPhase(c.Phase); ok {
		return p.CTEMStage
	}
	return ""
}

// Runnable reports whether the capability is routed.
func (c Capability) Runnable() bool { return c.Status == StatusRouted }

// Param returns the standard param with this name.
func (c Capability) Param(name string) (Param, bool) {
	for _, p := range c.Params {
		if p.Name == name {
			return p.clone(), true
		}
	}
	return Param{}, false
}

// Shapes are the named output shapes, in declaration order.
func (c Capability) Shapes() []string {
	var out []string
	for _, r := range c.Outputs {
		if r.Shape != "" && !contains(out, r.Shape) {
			out = append(out, r.Shape)
		}
	}
	return out
}

// Accepts reports whether a target of the CTIS asset type may be handed to
// the capability: one of its input ports carries it.
func (c Capability) Accepts(assetType string) bool {
	for _, p := range c.InPorts {
		if t, ok := LookupPortType(p); ok && contains(t.Carries, assetType) {
			return true
		}
	}
	return false
}

// MayEmit reports whether a report of the capability may carry an output of
// this kind: "asset:<ctis asset type>", "finding:<ctis finding type>" or
// "dependency". A capability may emit what its output ports carry, what its
// input ports carry (a tool re-observes its targets), its extra outputs, and
// findings of an allowed type when it has a finding output.
func (c Capability) MayEmit(kind string) bool { return c.mayEmit(tax.PortTypes, kind) }

func (c Capability) mayEmit(ports []PortTypeInfo, kind string) bool {
	family, value, _ := strings.Cut(kind, ":")
	switch family {
	case "asset":
		if value == "" {
			return false
		}
		if contains(c.ExtraOutputs, "asset:*") || contains(c.ExtraOutputs, kind) {
			return true
		}
		for _, p := range append(append([]PortType{}, c.OutPorts...), c.InPorts...) {
			if contains(carries(ports, p), value) {
				return true
			}
		}
		return false
	case "finding":
		if !containsPort(c.OutPorts, PortFinding) {
			return false
		}
		if len(c.FindingTypes) == 0 {
			return value != ""
		}
		return contains(c.FindingTypes, value)
	case "dependency":
		return value == "" && contains(c.ExtraOutputs, "dependency")
	}
	return false
}

func (p Param) clone() Param {
	p.Enum = append([]string(nil), p.Enum...)
	if p.Min != nil {
		v := *p.Min
		p.Min = &v
	}
	if p.Max != nil {
		v := *p.Max
		p.Max = &v
	}
	return p
}

func (c Capability) clone() Capability {
	c.InPorts = append([]PortType{}, c.InPorts...)
	c.OutPorts = append([]PortType{}, c.OutPorts...)
	c.ExtraOutputs = append([]string(nil), c.ExtraOutputs...)
	c.FindingTypes = append([]string(nil), c.FindingTypes...)
	params := make([]Param, len(c.Params))
	for i, p := range c.Params {
		params[i] = p.clone()
	}
	c.Params = params
	outputs := make([]Rule, len(c.Outputs))
	for i, r := range c.Outputs {
		r.Paths = append([]string(nil), r.Paths...)
		r.AnyOf = append([]string(nil), r.AnyOf...)
		outputs[i] = r
	}
	c.Outputs = outputs
	c.ATTACK = append([]string(nil), c.ATTACK...)
	c.D3FEND = append([]string(nil), c.D3FEND...)
	c.CAPEC = append([]string(nil), c.CAPEC...)
	if c.Deprecated != nil {
		d := *c.Deprecated
		c.Deprecated = &d
	}
	return c
}

// taxonomy is the decoded taxonomy.json.
type taxonomy struct {
	Version      int            `json:"version"`
	Phases       []PhaseInfo    `json:"phases"`
	PortTypes    []PortTypeInfo `json:"port_types"`
	Capabilities []Capability   `json:"capabilities"`
}

// tax is loaded in init, not in the declaration: validation reads the
// port table through the same accessors the package exports.
var tax taxonomy

func init() { tax = mustLoad(taxonomyJSON) }

func mustLoad(data []byte) taxonomy {
	t, err := load(data)
	if err != nil {
		panic("capability: embedded taxonomy is invalid: " + err.Error())
	}
	return t
}

func load(data []byte) (taxonomy, error) {
	var t taxonomy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return taxonomy{}, fmt.Errorf("decode: %w", err)
	}
	if err := t.validate(); err != nil {
		return taxonomy{}, err
	}
	return t, nil
}

// All returns every capability, in display order.
func All() []Capability {
	out := make([]Capability, len(tax.Capabilities))
	for i, c := range tax.Capabilities {
		out[i] = c.clone()
	}
	return out
}

// Routed returns the routed capabilities, in display order.
func Routed() []Capability {
	var out []Capability
	for _, c := range tax.Capabilities {
		if c.Status == StatusRouted {
			out = append(out, c.clone())
		}
	}
	return out
}

var refRE = regexp.MustCompile(`^([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)(?:@([1-9][0-9]{0,2}))?$`)

// ParseRef splits "scan.ports@1" into its id and major. A ref without a
// major ("scan.ports") returns major 0. ok is false for anything that is not
// a well-formed id; it does not say whether the capability exists.
func ParseRef(ref string) (id string, major int, ok bool) {
	m := refRE.FindStringSubmatch(ref)
	if m == nil {
		return "", 0, false
	}
	if m[2] != "" {
		major, _ = strconv.Atoi(m[2])
	}
	return m[1], major, true
}

// Lookup returns the capability a ref names. "scan.ports@1" names that
// major; "scan.ports" names its highest major. A ref is matched exactly:
// no case folding and no whitespace trimming.
func Lookup(ref string) (Capability, bool) {
	id, major, ok := ParseRef(ref)
	if !ok {
		return Capability{}, false
	}
	var best *Capability
	for i := range tax.Capabilities {
		c := &tax.Capabilities[i]
		if c.ID != id {
			continue
		}
		if major != 0 && c.Major == major {
			return c.clone(), true
		}
		if major == 0 && (best == nil || c.Major > best.Major) {
			best = c
		}
	}
	if best == nil {
		return Capability{}, false
	}
	return best.clone(), true
}

// Phases returns the closed phase set, in order.
func Phases() []PhaseInfo { return append([]PhaseInfo(nil), tax.Phases...) }

// LookupPhase returns a phase's description.
func LookupPhase(p Phase) (PhaseInfo, bool) {
	for _, ph := range tax.Phases {
		if ph.ID == p {
			return ph, true
		}
	}
	return PhaseInfo{}, false
}

// PortTypes returns the closed port type set, in display order.
func PortTypes() []PortTypeInfo {
	out := make([]PortTypeInfo, len(tax.PortTypes))
	for i, p := range tax.PortTypes {
		p.Carries = append([]string{}, p.Carries...)
		out[i] = p
	}
	return out
}

// LookupPortType returns a port type's description.
func LookupPortType(t PortType) (PortTypeInfo, bool) {
	for _, p := range tax.PortTypes {
		if p.Type == t {
			p.Carries = append([]string{}, p.Carries...)
			return p, true
		}
	}
	return PortTypeInfo{}, false
}

// JSON returns the embedded taxonomy document, for tools that render or
// export it.
func JSON() []byte { return append([]byte(nil), taxonomyJSON...) }

func carries(ports []PortTypeInfo, t PortType) []string {
	for _, p := range ports {
		if p.Type == t {
			return p.Carries
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsPort(list []PortType, p PortType) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}
