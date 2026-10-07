package capability

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/openctemio/ctis"
)

// Identifier formats of the framework references a capability carries.
var (
	attackRE = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	d3fendRE = regexp.MustCompile(`^D3-[A-Z]{2,8}$`)
	capecRE  = regexp.MustCompile(`^CAPEC-[0-9]{1,5}$`)
	nameRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	selectRE = regexp.MustCompile(`^(assets|findings|dependencies|endpoints)(?:\[type=([a-z0-9_]+(?:\|[a-z0-9_]+)*)\])?$`)
	pathRE   = regexp.MustCompile(`^[a-z_][a-z0-9_]*(?:\[\])?(?:\.[a-z_][a-z0-9_]*(?:\[\])?)*$`)
)

// AssetTypes are the CTIS asset type names this taxonomy may refer to.
func knownAssetTypes() map[string]bool {
	out := map[string]bool{}
	for _, t := range ctis.AllAssetTypes() {
		out[string(t)] = true
	}
	return out
}

var knownFindingTypes = map[string]bool{
	string(ctis.FindingTypeVulnerability):    true,
	string(ctis.FindingTypeSecret):           true,
	string(ctis.FindingTypeMisconfiguration): true,
	string(ctis.FindingTypeCompliance):       true,
	string(ctis.FindingTypeWeb3):             true,
}

func (t taxonomy) validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if t.Version != Version {
		add("version %d, want %d", t.Version, Version)
	}
	assetTypes := knownAssetTypes()

	phases := map[Phase]bool{}
	for _, p := range t.Phases {
		switch p.ID {
		case PhaseDiscoverPassive, PhaseDiscoverActive, PhaseAssess, PhaseValidate, PhaseCollect:
		default:
			add("phase %q: not in the closed set", p.ID)
		}
		if p.CTEMStage != "discovery" && p.CTEMStage != "validation" {
			add("phase %q: ctem_stage %q", p.ID, p.CTEMStage)
		}
		if phases[p.ID] {
			add("phase %q: duplicate", p.ID)
		}
		phases[p.ID] = true
	}

	ports := map[PortType]bool{}
	for _, p := range t.PortTypes {
		if !nameRE.MatchString(string(p.Type)) || p.Label == "" {
			add("port type %q: bad name or empty label", p.Type)
		}
		if ports[p.Type] {
			add("port type %q: duplicate", p.Type)
		}
		ports[p.Type] = true
		if p.Type != PortFinding && p.Type != PortEndpoint && len(p.Carries) == 0 {
			add("port type %q carries nothing", p.Type)
		}
		for _, c := range p.Carries {
			if !assetTypes[c] {
				add("port type %q: carries unknown CTIS asset type %q", p.Type, c)
			}
		}
	}

	seen := map[string]bool{}
	for _, c := range t.Capabilities {
		ref := c.Ref()
		where := "capability " + ref
		if _, _, ok := ParseRef(ref); !ok || c.Major < 1 {
			add("%s: malformed id or major", where)
		}
		if seen[ref] {
			add("%s: duplicate", where)
		}
		seen[ref] = true
		if c.Name == "" || c.Description == "" {
			add("%s: name and description are required", where)
		}
		switch c.Status {
		case StatusRouted, StatusPlanned, StatusLater:
		default:
			add("%s: status %q", where, c.Status)
		}
		if !phases[c.Phase] {
			add("%s: unknown phase %q", where, c.Phase)
		}
		if c.TierFloor < 0 || c.TierFloor > 2 {
			add("%s: tier_floor %d outside 0..2", where, c.TierFloor)
		}
		// A validation act never runs below T0 by phase, but an active
		// phase can never be passive.
		if c.Phase == PhaseDiscoverActive && c.TierFloor < 1 {
			add("%s: an active phase needs tier_floor >= 1", where)
		}
		for _, p := range c.InPorts {
			if !ports[p] {
				add("%s: unknown in port %q", where, p)
			}
		}
		for _, p := range c.OutPorts {
			if !ports[p] {
				add("%s: unknown out port %q", where, p)
			}
		}
		if len(c.InPorts) == 0 && !c.CrossCutting && c.Status != StatusLater {
			add("%s: a workflow capability needs an input port", where)
		}
		if len(c.OutPorts) == 0 && len(c.ExtraOutputs) == 0 {
			add("%s: emits nothing", where)
		}
		for _, k := range c.ExtraOutputs {
			family, value, _ := strings.Cut(k, ":")
			switch {
			case k == "dependency", k == "endpoint":
			case family == "asset" && (value == "*" || assetTypes[value]):
			default:
				add("%s: extra output %q", where, k)
			}
		}
		for _, ft := range c.FindingTypes {
			if !knownFindingTypes[ft] {
				add("%s: unknown finding type %q", where, ft)
			}
		}
		if len(c.FindingTypes) > 0 && !containsPort(c.OutPorts, PortFinding) {
			add("%s: finding_types without a finding output", where)
		}
		params := map[string]bool{}
		for _, p := range c.Params {
			if err := p.validate(); err != nil {
				add("%s: param %q: %v", where, p.Name, err)
			}
			if params[p.Name] {
				add("%s: param %q: duplicate", where, p.Name)
			}
			params[p.Name] = true
		}
		if c.Status == StatusRouted && !c.CrossCutting && len(c.Outputs) == 0 {
			add("%s: a routed capability needs required-output rules", where)
		}
		for i, r := range c.Outputs {
			if err := r.validate(c, t.PortTypes); err != nil {
				add("%s: outputs[%d]: %v", where, i, err)
			}
		}
		for _, id := range c.ATTACK {
			if !attackRE.MatchString(id) {
				add("%s: ATT&CK id %q", where, id)
			}
		}
		for _, id := range c.D3FEND {
			if !d3fendRE.MatchString(id) {
				add("%s: D3FEND id %q", where, id)
			}
		}
		for _, id := range c.CAPEC {
			if !capecRE.MatchString(id) {
				add("%s: CAPEC id %q", where, id)
			}
		}
		if d := c.Deprecated; d != nil && d.Since == "" {
			add("%s: deprecated needs since", where)
		}
	}
	return errors.Join(errs...)
}

func (p Param) validate() error {
	if !nameRE.MatchString(p.Name) {
		return errors.New("bad name")
	}
	if p.Description == "" {
		return errors.New("description is required")
	}
	switch p.Type {
	case ParamString, ParamStringList:
	case ParamInteger:
		if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
			return errors.New("min > max")
		}
	case ParamBoolean, ParamPortList:
		if len(p.Enum) > 0 {
			return errors.New("enum on a boolean or port list")
		}
	default:
		return fmt.Errorf("type %q", p.Type)
	}
	if p.Type != ParamInteger && (p.Min != nil || p.Max != nil) {
		return errors.New("min/max on a non-integer")
	}
	return nil
}

func (r Rule) validate(c Capability, ports []PortTypeInfo) error {
	m := selectRE.FindStringSubmatch(r.Select)
	if m == nil {
		return fmt.Errorf("select %q", r.Select)
	}
	if r.Shape != "" && !nameRE.MatchString(r.Shape) {
		return fmt.Errorf("shape %q", r.Shape)
	}
	if len(r.Paths) == 0 && len(r.AnyOf) == 0 {
		return errors.New("no paths")
	}
	if len(r.AnyOf) == 1 {
		return errors.New("any_of with one path is a path")
	}
	var root reflect.Type
	switch m[1] {
	case "assets":
		root = reflect.TypeOf(ctis.Asset{})
		for _, at := range splitTypes(m[2]) {
			if !c.mayEmit(ports, "asset:"+at) {
				return fmt.Errorf("select %q: the capability cannot emit asset %q", r.Select, at)
			}
		}
	case "findings":
		root = reflect.TypeOf(ctis.Finding{})
		if !containsPort(c.OutPorts, PortFinding) {
			return fmt.Errorf("select %q: the capability emits no findings", r.Select)
		}
		for _, ft := range splitTypes(m[2]) {
			if !c.mayEmit(ports, "finding:"+ft) {
				return fmt.Errorf("select %q: finding type %q", r.Select, ft)
			}
		}
	case "endpoints":
		root = reflect.TypeOf(ctis.Endpoint{})
		if m[2] != "" {
			return errors.New("endpoints take no type filter")
		}
		if !c.mayEmit(ports, "endpoint") {
			return fmt.Errorf("select %q: the capability emits no endpoints", r.Select)
		}
	case "dependencies":
		root = reflect.TypeOf(ctis.Dependency{})
		if m[2] != "" {
			return errors.New("dependencies take no type filter")
		}
		if !c.mayEmit(ports, "dependency") {
			return fmt.Errorf("select %q: the capability emits no dependencies", r.Select)
		}
	}
	for _, p := range append(append([]string{}, r.Paths...), r.AnyOf...) {
		if err := resolvePath(root, p); err != nil {
			return fmt.Errorf("path %q: %w", p, err)
		}
	}
	return nil
}

func splitTypes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "|")
}

// resolvePath checks that a rule path names members of the CTIS Go type, by
// their JSON names. A member of a free-form map (properties, details) may
// carry any key below it.
func resolvePath(t reflect.Type, path string) error {
	if !pathRE.MatchString(path) {
		return errors.New("malformed")
	}
	for _, seg := range strings.Split(path, ".") {
		name, list := strings.CutSuffix(seg, "[]")
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch t.Kind() {
		case reflect.Map, reflect.Interface:
			return nil // free-form below this point
		case reflect.Struct:
		default:
			return fmt.Errorf("%q is below a scalar", name)
		}
		f, ok := jsonField(t, name)
		if !ok {
			return fmt.Errorf("%s has no member %q", t.Name(), name)
		}
		t = f
		if list {
			for t.Kind() == reflect.Pointer {
				t = t.Elem()
			}
			if t.Kind() != reflect.Slice {
				return fmt.Errorf("%q is not a list", name)
			}
			t = t.Elem()
		}
	}
	return nil
}

func jsonField(t reflect.Type, name string) (reflect.Type, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == name {
			return f.Type, true
		}
	}
	return nil, false
}
