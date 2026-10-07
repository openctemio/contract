package capability

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

// mutate decodes the embedded taxonomy, applies f and re-encodes it.
func mutate(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(taxonomyJSON, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func capAt(m map[string]any, id string) map[string]any {
	for _, c := range m["capabilities"].([]any) {
		cm := c.(map[string]any)
		if cm["id"] == id {
			return cm
		}
	}
	return nil
}

func TestLoadRefusesBadTaxonomies(t *testing.T) {
	cases := map[string]struct {
		f    func(m map[string]any)
		want string
	}{
		"unknown member": {func(m map[string]any) { capAt(m, "scan.ports")["ports"] = []any{"x"} }, "unknown field"},
		"version":        {func(m map[string]any) { m["version"] = 2 }, "version 2"},
		"duplicate id": {func(m map[string]any) {
			m["capabilities"] = append(m["capabilities"].([]any), capAt(m, "scan.ports"))
		}, "duplicate"},
		"bad id":            {func(m map[string]any) { capAt(m, "scan.ports")["id"] = "Scan" }, "malformed id"},
		"major zero":        {func(m map[string]any) { capAt(m, "scan.ports")["major"] = 0 }, "malformed id"},
		"no name":           {func(m map[string]any) { capAt(m, "scan.ports")["name"] = "" }, "name and description"},
		"status":            {func(m map[string]any) { capAt(m, "scan.ports")["status"] = "beta" }, "status"},
		"phase":             {func(m map[string]any) { capAt(m, "scan.ports")["phase"] = "recon" }, "unknown phase"},
		"tier":              {func(m map[string]any) { capAt(m, "scan.ports")["tier_floor"] = 3 }, "tier_floor"},
		"active passive":    {func(m map[string]any) { capAt(m, "scan.ports")["tier_floor"] = 0 }, "active phase"},
		"in port":           {func(m map[string]any) { capAt(m, "scan.ports")["in_ports"] = []any{"email"} }, "unknown in port"},
		"out port":          {func(m map[string]any) { capAt(m, "scan.ports")["out_ports"] = []any{"email"} }, "unknown out port"},
		"no input":          {func(m map[string]any) { capAt(m, "sast.code")["in_ports"] = []any{} }, "needs an input port"},
		"emits nothing":     {func(m map[string]any) { capAt(m, "sast.code")["out_ports"] = []any{} }, "emits nothing"},
		"extra output":      {func(m map[string]any) { capAt(m, "probe.http")["extra_outputs"] = []any{"asset:nope"} }, "extra output"},
		"finding type":      {func(m map[string]any) { capAt(m, "secrets.code")["finding_types"] = []any{"nope"} }, "unknown finding type"},
		"types no findings": {func(m map[string]any) { capAt(m, "scan.ports")["finding_types"] = []any{"secret"} }, "without a finding output"},
		"param type": {func(m map[string]any) {
			capAt(m, "sast.code")["params"] = []any{map[string]any{"name": "x", "type": "float", "description": "d"}}
		}, "type \"float\""},
		"param dup": {func(m map[string]any) {
			p := map[string]any{"name": "x", "type": "string", "description": "d"}
			capAt(m, "sast.code")["params"] = []any{p, p}
		}, "duplicate"},
		"param min max": {func(m map[string]any) {
			capAt(m, "sast.code")["params"] = []any{map[string]any{"name": "x", "type": "integer", "description": "d", "min": 5, "max": 1}}
		}, "min > max"},
		"param bool enum": {func(m map[string]any) {
			capAt(m, "sast.code")["params"] = []any{map[string]any{"name": "x", "type": "boolean", "description": "d", "enum": []any{"a"}}}
		}, "enum on a boolean"},
		"param string min": {func(m map[string]any) {
			capAt(m, "sast.code")["params"] = []any{map[string]any{"name": "x", "type": "string", "description": "d", "min": 1}}
		}, "min/max on a non-integer"},
		"param name": {func(m map[string]any) {
			capAt(m, "sast.code")["params"] = []any{map[string]any{"name": "X y", "type": "string", "description": "d"}}
		}, "bad name"},
		"param desc": {func(m map[string]any) {
			capAt(m, "sast.code")["params"] = []any{map[string]any{"name": "x", "type": "string"}}
		}, "description is required"},
		"routed no rules": {func(m map[string]any) { capAt(m, "sast.code")["outputs"] = []any{} }, "required-output rules"},
		"select": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "things", "paths": []any{"x"}}}
		}, "select"},
		"select asset not emitted": {func(m map[string]any) {
			capAt(m, "scan.ports")["outputs"] = []any{map[string]any{"select": "assets[type=repository]", "paths": []any{"value"}}}
		}, "cannot emit asset"},
		"select findings none": {func(m map[string]any) {
			capAt(m, "scan.ports")["outputs"] = []any{map[string]any{"select": "findings", "paths": []any{"title"}}}
		}, "emits no findings"},
		"select finding type": {func(m map[string]any) {
			capAt(m, "secrets.code")["outputs"] = []any{map[string]any{"select": "findings[type=vulnerability]", "paths": []any{"title"}}}
		}, "finding type"},
		"select deps filter": {func(m map[string]any) {
			capAt(m, "sca.deps")["outputs"] = []any{map[string]any{"select": "dependencies[type=x]", "paths": []any{"name"}}}
		}, "no type filter"},
		"select deps none": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "dependencies", "paths": []any{"name"}}}
		}, "emits no dependencies"},
		"no paths": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "findings"}}
		}, "no paths"},
		"any_of one": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "findings", "any_of": []any{"title"}}}
		}, "any_of with one path"},
		"shape name": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"shape": "Bad Shape", "select": "findings", "paths": []any{"title"}}}
		}, "shape"},
		"unknown path": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "findings", "paths": []any{"location.file"}}}
		}, "has no member \"file\""},
		"path not list": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "findings", "paths": []any{"title[]"}}}
		}, "not a list"},
		"path below scalar": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "findings", "paths": []any{"title.x"}}}
		}, "below a scalar"},
		"path malformed": {func(m map[string]any) {
			capAt(m, "sast.code")["outputs"] = []any{map[string]any{"select": "findings", "paths": []any{"../x"}}}
		}, "malformed"},
		"attack": {func(m map[string]any) { capAt(m, "scan.ports")["attack"] = []any{"T1"} }, "ATT&CK id"},
		"d3fend": {func(m map[string]any) { capAt(m, "scan.ports")["d3fend"] = []any{"x"} }, "D3FEND id"},
		"capec":  {func(m map[string]any) { capAt(m, "scan.ports")["capec"] = []any{"x"} }, "CAPEC id"},
		"deprecated": {func(m map[string]any) {
			capAt(m, "scan.ports")["deprecated"] = map[string]any{"message": "m"}
		}, "deprecated needs since"},
		"phase set":       {func(m map[string]any) { m["phases"].([]any)[0].(map[string]any)["id"] = "x" }, "closed set"},
		"phase stage":     {func(m map[string]any) { m["phases"].([]any)[0].(map[string]any)["ctem_stage"] = "x" }, "ctem_stage"},
		"phase duplicate": {func(m map[string]any) { m["phases"] = append(m["phases"].([]any), m["phases"].([]any)[0]) }, "duplicate"},
		"port label":      {func(m map[string]any) { m["port_types"].([]any)[0].(map[string]any)["label"] = "" }, "empty label"},
		"port duplicate": {func(m map[string]any) {
			m["port_types"] = append(m["port_types"].([]any), m["port_types"].([]any)[0])
		}, "duplicate"},
		"port carries nothing": {func(m map[string]any) { m["port_types"].([]any)[0].(map[string]any)["carries"] = []any{} }, "carries nothing"},
		"port carries unknown": {func(m map[string]any) {
			m["port_types"].([]any)[0].(map[string]any)["carries"] = []any{"email"}
		}, "unknown CTIS asset type"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(mutate(t, tc.f))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	if _, err := load([]byte("{")); err == nil {
		t.Fatal("truncated JSON")
	}
}

func TestMustLoadPanicsOnInvalidData(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	mustLoad([]byte(`{"version":9}`))
}

func TestResolvePathFreeForm(t *testing.T) {
	asset := reflect.TypeOf(ctis.Asset{})
	for _, p := range []string{"properties.anything.below", "technical.service.details.x", "technical.domain.dns_records[].type"} {
		if err := resolvePath(asset, p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
