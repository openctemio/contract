package capability

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func mustLookup(t *testing.T, ref string) Capability {
	t.Helper()
	c, ok := Lookup(ref)
	if !ok {
		t.Fatalf("%s missing", ref)
	}
	return c
}

// doc decodes a CTIS JSON document, the form Check takes.
func doc(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCheckConformingOutputs(t *testing.T) {
	cases := map[string]string{
		"discover.subdomains@1": `{"assets":[{"type":"domain_name","value":"a.example.com"}]}`,
		"resolve.dns@1":         `{"assets":[{"type":"domain_name","value":"a.example.com","technical":{"domain":{"dns_records":[{"type":"A","value":"192.0.2.1"}]}}}]}`,
		"probe.http@1":          `{"assets":[{"type":"web_origin","value":"https://a.example.com","technical":{"http":{"status_code":200}}}]}`,
		"crawl.web@1":           `{"endpoints":[{"origin":"https://a.example.com","path":"/login"}]}`,
	}
	for ref, in := range cases {
		v, err := mustLookup(t, ref).Check(doc(t, in), CheckOptions{})
		if err != nil || len(v) != 0 {
			t.Errorf("%s: violations %v, err %v", ref, v, err)
		}
	}
}

func TestCheckScanPortsOutputs(t *testing.T) {
	// In CTIS 2.0 an open port is a service asset (host:port/transport).
	c := mustLookup(t, "scan.ports@1")
	ok := doc(t, `{"assets":[{"type":"service","value":"192.0.2.1:443/tcp","technical":{"service":{"port":443,"transport":"tcp"}}}]}`)
	if v, err := c.Check(ok, CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("service asset: %v %v", v, err)
	}
	bad := doc(t, `{"assets":[{"type":"service","value":"192.0.2.1:443/tcp"}]}`)
	v, _ := c.Check(bad, CheckOptions{})
	if len(v) != 2 || v[0].Path != "technical.service.port" || v[1].Path != "technical.service.transport" || v[0].Record != "/assets/0" {
		t.Fatalf("service without port = %v", v)
	}
}

func TestCheckRefusesUndeclaredOutputs(t *testing.T) {
	c := mustLookup(t, "scan.ports@1")
	r := doc(t, `{"assets":[{"type":"repository","value":"github.com/a/b"}],
		"findings":[{"type":"vulnerability","title":"x"}],"dependencies":[{"name":"x"}]}`)
	v, err := c.Check(r, CheckOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, x := range v {
		if x.Kind != "not_allowed" {
			t.Errorf("unexpected %v", x)
		}
		kinds = append(kinds, x.Path)
	}
	if strings.Join(kinds, ",") != "asset:repository,finding:vulnerability,dependency" {
		t.Fatalf("kinds = %v", kinds)
	}
	if !strings.Contains(v[0].String(), "not an output") {
		t.Error(v[0].String())
	}
}

func TestCheckSecretsNeedMaskedValue(t *testing.T) {
	c := mustLookup(t, "secrets.code@1")
	r := doc(t, `{"findings":[{"type":"secret","title":"AWS key","rule_id":"aws-access-key","location":{"path":"config.yml","start_line":3}}]}`)
	v, _ := c.Check(r, CheckOptions{})
	if len(v) != 1 || v[0].Path != "secret.masked_value" || !strings.Contains(v[0].String(), "missing") {
		t.Fatalf("violations = %v", v)
	}
	r = doc(t, `{"findings":[{"type":"secret","title":"AWS key","rule_id":"aws-access-key","location":{"path":"config.yml","start_line":3},"secret":{"masked_value":"AKIA****"}}]}`)
	if v, _ := c.Check(r, CheckOptions{}); len(v) != 0 {
		t.Fatalf("violations = %v", v)
	}
}

func TestCheckAnyOf(t *testing.T) {
	c := mustLookup(t, "vuln.templates@1")
	r := doc(t, `{"findings":[{"type":"vulnerability","title":"t","rule_id":"r","severity":"high"}]}`)
	v, _ := c.Check(r, CheckOptions{})
	if len(v) != 1 || v[0].Kind != "missing_any_of" || !strings.Contains(v[0].String(), "needs one of") {
		t.Fatalf("violations = %v", v)
	}
	r = doc(t, `{"findings":[{"type":"vulnerability","title":"t","rule_id":"r","severity":"high","network":{"host":"a.example.com","port":443}}]}`)
	if v, _ := c.Check(r, CheckOptions{}); len(v) != 0 {
		t.Fatalf("violations = %v", v)
	}
}

func TestCheckIsBounded(t *testing.T) {
	c := mustLookup(t, "sast.code@1")
	recs := func(n int, typ string) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"type": typ}
		}
		return out
	}
	r := map[string]any{"findings": recs(1000, "vulnerability")}
	v, _ := c.Check(r, CheckOptions{})
	if len(v) != 100 {
		t.Fatalf("default cap: %d", len(v))
	}
	v, _ = c.Check(r, CheckOptions{MaxViolations: 3})
	if len(v) != 3 {
		t.Fatalf("cap 3: %d", len(v))
	}
	// The cap holds while undeclared outputs are counted too.
	r["assets"] = recs(200, "host")
	if v, _ := c.Check(r, CheckOptions{MaxViolations: 5}); len(v) != 5 {
		t.Fatalf("cap on assets: %d", len(v))
	}
	delete(r, "assets")
	r["findings"] = recs(200, "web3")
	if v, _ := c.Check(r, CheckOptions{MaxViolations: 5}); len(v) != 5 {
		t.Fatalf("cap on findings: %d", len(v))
	}
}

func TestCheckNilAndEmpty(t *testing.T) {
	c := mustLookup(t, "sca.deps@1")
	if v, err := c.Check(nil, CheckOptions{}); v != nil || err != nil {
		t.Fatal("nil report")
	}
	if v, _ := c.Check(map[string]any{}, CheckOptions{}); len(v) != 0 {
		t.Fatal("an empty result conforms")
	}
	v, _ := c.Check(doc(t, `{"dependencies":[{"name":"lodash"}]}`), CheckOptions{})
	if len(v) != 1 || v[0].Path != "version" || v[0].Record != "/dependencies/0" {
		t.Fatalf("violations = %v", v)
	}
}

func TestPresent(t *testing.T) {
	doc := map[string]any{
		"s": "  ", "n": 0.0, "b": false, "l": []any{}, "m": map[string]any{},
		"list": []any{map[string]any{"x": "1"}, "scalar"},
	}
	for path, want := range map[string]bool{
		"s": false, "n": true, "b": true, "l": false, "m": false, "missing": false,
		"list[].x": false, "s.x": false, "n[]": false,
	} {
		if got := present(doc, strings.Split(path, ".")); got != want {
			t.Errorf("present(%s) = %v", path, got)
		}
	}
}

// Endpoints are an output kind of their own: a capability with an endpoint
// port, in or out, or the endpoint extra output may report them.
func TestEndpointOutputs(t *testing.T) {
	crawl, _ := Lookup("crawl.web@1")
	dast, _ := Lookup("dast.web@1")
	ports, _ := Lookup("scan.ports@1")
	probe, _ := Lookup("probe.http@1")
	spec, ok := Lookup("import.api_spec@1")
	if !ok || spec.Status != StatusPlanned || spec.Phase != PhaseCollect || spec.TierFloor != 0 || len(spec.InPorts) != 0 {
		t.Fatalf("import.api_spec %+v", spec)
	}
	for _, c := range []Capability{crawl, dast, probe, spec} {
		if !c.MayEmit("endpoint") {
			t.Errorf("%s may emit endpoints", c.Ref())
		}
	}
	if ports.MayEmit("endpoint") || crawl.MayEmit("endpoint:x") {
		t.Error("scan.ports emits no endpoints; endpoint takes no type")
	}
	if p, ok := probe.Param("api_schema"); !ok || p.Type != ParamBoolean {
		t.Error("probe.http api_schema")
	}
	r := doc(t, `{"endpoints":[{"origin":"https://a.example","path":"/x"},{"origin":"https://a.example"}]}`)
	v, err := crawl.Check(r, CheckOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0].Kind != "missing_path" || v[0].Record != "/endpoints/1" || v[0].Path != "path" {
		t.Fatalf("crawl violations %v", v)
	}
	v, _ = ports.Check(r, CheckOptions{})
	if len(v) != 1 || v[0].Kind != "not_allowed" || v[0].Record != "/endpoints" {
		t.Fatalf("scan.ports violations %v", v)
	}
	// A web finding located by finding.web conforms to dast.web and
	// vuln.templates.
	f := doc(t, `{"findings":[{"rule_id":"r","severity":"high","title":"t","type":"vulnerability","web":{"url":"https://a.example/x"}}]}`)
	for _, id := range []string{"dast.web@1", "vuln.templates@1"} {
		c, _ := Lookup(id)
		if !c.Accepts("web_origin") {
			t.Errorf("%s keeps its url input", id)
		}
		if !containsPort(c.InPorts, PortEndpoint) {
			t.Errorf("%s takes endpoints", id)
		}
		if v, _ := c.Check(f, CheckOptions{}); v != nil {
			t.Errorf("%s: %v", id, v)
		}
	}
}

func TestEndpointRuleValidation(t *testing.T) {
	tax, err := load(taxonomyJSON)
	if err != nil {
		t.Fatal(err)
	}
	c := tax.Capabilities[0]
	c.OutPorts, c.ExtraOutputs = []PortType{PortHostname}, nil
	for sel, want := range map[string]string{
		"endpoints":            "emits no endpoints",
		"endpoints[type=page]": "no type filter",
	} {
		if err := (Rule{Select: sel, Paths: []string{"origin"}}).validate(c, tax.PortTypes); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", sel, err)
		}
	}
	c.ExtraOutputs = []string{"endpoint"}
	if err := (Rule{Select: "endpoints", Paths: []string{"origin", "params[].name"}}).validate(c, tax.PortTypes); err != nil {
		t.Error(err)
	}
	if err := (Rule{Select: "endpoints", Paths: []string{"Nope"}}).validate(c, tax.PortTypes); err == nil {
		t.Error("a malformed path")
	}
}

func TestCheckLookupOutputs(t *testing.T) {
	// lookup.rdap re-observes the root domain with its registration data;
	// an address is not an output of it.
	rdap := mustLookup(t, "lookup.rdap@1")
	good := doc(t, `{"assets":[{"type":"domain_name","value":"example.com","technical":{"domain":{"registrar":"Example Registrar","whois":{"rdap_server":"https://rdap.example/"}}}}]}`)
	if v, err := rdap.Check(good, CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("rdap: %v %v", v, err)
	}
	bad := doc(t, `{"assets":[{"type":"domain_name","value":"example.com"},{"type":"ip_address","value":"192.0.2.1"}]}`)
	v, _ := rdap.Check(bad, CheckOptions{})
	if len(v) != 2 || v[0].Kind != "not_allowed" || v[1].Path != "technical.domain.whois" {
		t.Fatalf("rdap bad = %v", v)
	}
	// lookup.asn annotates the address and may report announced ranges as
	// ranges, each with its origin system.
	asn := mustLookup(t, "lookup.asn@1")
	r := doc(t, `{"assets":[
		{"type":"ip_address","value":"192.0.2.1","technical":{"ip_address":{"asn":64496}}},
		{"type":"ip_range","value":"192.0.2.0/24","technical":{"ip_address":{"asn":64496}}}]}`)
	if v, err := asn.Check(r, CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("asn: %v %v", v, err)
	}
	delete(r["assets"].([]any)[1].(map[string]any), "technical")
	if v, _ := asn.Check(r, CheckOptions{}); len(v) != 1 || v[0].Path != "technical.ip_address.asn" {
		t.Fatalf("range without technical.ip_address.asn = %v", v)
	}
	if c, _ := Lookup("lookup.asn@1"); c.TierFloor != 0 || c.Phase != "discover.passive" || !c.Runnable() {
		t.Fatalf("asn = %+v", c)
	}
}

func TestCheckDiscoverHostsOutputs(t *testing.T) {
	// discover.hosts reports each live address with when it answered
	// (last_seen_at); an address without it, or a name, is not an output of it.
	c := mustLookup(t, "discover.hosts@1")
	live := doc(t, `{"assets":[{"type":"ip_address","value":"192.0.2.7","last_seen_at":"2026-11-03T00:00:00Z"}]}`)
	if v, err := c.Check(live, CheckOptions{}); err != nil || len(v) != 0 {
		t.Fatalf("live address: %v %v", v, err)
	}
	bad := doc(t, `{"assets":[{"type":"ip_address","value":"192.0.2.8"},{"type":"domain_name","value":"www.example.com"}]}`)
	v, _ := c.Check(bad, CheckOptions{})
	if len(v) != 2 || v[0].Kind != "not_allowed" || v[1].Path != "last_seen_at" {
		t.Fatalf("discover.hosts bad = %v", v)
	}
	if c.TierFloor != 1 || c.Phase != "discover.active" || !c.Runnable() ||
		!slices.Equal(c.InPorts, []PortType{"ip", "cidr"}) || !slices.Equal(c.OutPorts, []PortType{"ip"}) {
		t.Fatalf("discover.hosts = %+v", c)
	}
}
