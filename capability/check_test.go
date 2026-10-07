package capability

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func mustLookup(t *testing.T, ref string) Capability {
	t.Helper()
	c, ok := Lookup(ref)
	if !ok {
		t.Fatalf("%s missing", ref)
	}
	return c
}

func TestCheckConformingReconOutput(t *testing.T) {
	// Real converter output for each recon capability conforms.
	cases := map[string]*ctis.ReconToCTISInput{
		"discover.subdomains@1": {ScannerName: "subfinder", ReconType: "subdomain", Target: "example.com",
			Subdomains: []ctis.SubdomainInput{{Host: "a.example.com", Domain: "example.com", Source: "crt"}}},
		"resolve.dns@1": {ScannerName: "dnsx", ReconType: "dns", Target: "example.com",
			DNSRecords: []ctis.DNSRecordInput{{Host: "a.example.com", RecordType: "A", Values: []string{"192.0.2.1"}}}},
		"probe.http@1": {ScannerName: "httpx", ReconType: "http_probe", Target: "a.example.com",
			LiveHosts: []ctis.LiveHostInput{{URL: "https://a.example.com", Host: "a.example.com", StatusCode: 200, Scheme: "https", Port: 443}}},
		"crawl.web@1": {ScannerName: "katana", ReconType: "url_crawl", Target: "https://a.example.com",
			URLs: []ctis.DiscoveredURLInput{{URL: "https://a.example.com/login", Method: "GET"}}},
	}
	for ref, in := range cases {
		r, err := ctis.ConvertReconToCTIS(in, nil)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		v, err := mustLookup(t, ref).Check(r, CheckOptions{})
		if err != nil || len(v) != 0 {
			t.Errorf("%s: violations %v, err %v", ref, v, err)
		}
	}
}

func TestCheckScanPortsShapes(t *testing.T) {
	c := mustLookup(t, "scan.ports@1")
	in := &ctis.ReconToCTISInput{ScannerName: "naabu", ReconType: "port", Target: "192.0.2.1",
		OpenPorts: []ctis.OpenPortInput{{IP: "192.0.2.1", Port: 443, Protocol: "tcp"}}}
	opts := ctis.DefaultReconConverterOptions()
	for _, group := range []bool{true, false} {
		opts.GroupByIP = group
		r, err := ctis.ConvertReconToCTIS(in, opts)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := c.Check(r, CheckOptions{}); len(v) != 0 {
			t.Errorf("group=%v: %v", group, v)
		}
	}
	// An IP asset without ports misses the ip_ports shape unless the tool
	// declared the other shape.
	r := &ctis.Report{Assets: []ctis.Asset{{Type: ctis.AssetTypeIPAddress, Value: "192.0.2.1"}}}
	v, _ := c.Check(r, CheckOptions{})
	if len(v) != 1 || v[0].Path != "technical.ip_address.ports[].port" || v[0].Record != "/assets/0" {
		t.Fatalf("violations = %v", v)
	}
	if v, _ := c.Check(r, CheckOptions{Shape: "open_port_assets"}); len(v) != 0 {
		t.Fatalf("shape-filtered = %v", v)
	}
	// An empty ports list is missing, not present.
	r.Assets[0].Technical = &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{}}
	if v, _ := c.Check(r, CheckOptions{}); len(v) != 1 {
		t.Fatalf("empty list = %v", v)
	}
}

func TestCheckRefusesUndeclaredOutputs(t *testing.T) {
	c := mustLookup(t, "scan.ports@1")
	r := &ctis.Report{
		Assets:       []ctis.Asset{{Type: ctis.AssetTypeRepository, Value: "github.com/a/b"}},
		Findings:     []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "x"}},
		Dependencies: []ctis.Dependency{{Name: "x"}},
	}
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
	f := ctis.Finding{Type: ctis.FindingTypeSecret, Title: "AWS key", RuleID: "aws-access-key",
		Location: &ctis.FindingLocation{Path: "config.yml", StartLine: 3}}
	r := &ctis.Report{Findings: []ctis.Finding{f}}
	v, _ := c.Check(r, CheckOptions{})
	if len(v) != 1 || v[0].Path != "secret.masked_value" || !strings.Contains(v[0].String(), "missing") {
		t.Fatalf("violations = %v", v)
	}
	r.Findings[0].Secret = &ctis.SecretDetails{MaskedValue: "AKIA****"}
	if v, _ := c.Check(r, CheckOptions{}); len(v) != 0 {
		t.Fatalf("violations = %v", v)
	}
}

func TestCheckAnyOf(t *testing.T) {
	c := mustLookup(t, "vuln.templates@1")
	r := &ctis.Report{Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "t", RuleID: "r", Severity: ctis.SeverityHigh}}}
	v, _ := c.Check(r, CheckOptions{})
	if len(v) != 1 || v[0].Kind != "missing_any_of" || !strings.Contains(v[0].String(), "needs one of") {
		t.Fatalf("violations = %v", v)
	}
	r.Findings[0].Network = &ctis.NetworkLocation{Host: "a.example.com", Port: 443}
	if v, _ := c.Check(r, CheckOptions{}); len(v) != 0 {
		t.Fatalf("violations = %v", v)
	}
}

func TestCheckIsBounded(t *testing.T) {
	c := mustLookup(t, "sast.code@1")
	r := &ctis.Report{}
	for i := 0; i < 1000; i++ {
		r.Findings = append(r.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability})
	}
	v, _ := c.Check(r, CheckOptions{})
	if len(v) != 100 {
		t.Fatalf("default cap: %d", len(v))
	}
	v, _ = c.Check(r, CheckOptions{MaxViolations: 3})
	if len(v) != 3 {
		t.Fatalf("cap 3: %d", len(v))
	}
	// The cap holds while undeclared outputs are counted too.
	r.Assets = make([]ctis.Asset, 200)
	if v, _ := c.Check(r, CheckOptions{MaxViolations: 5}); len(v) != 5 {
		t.Fatalf("cap on assets: %d", len(v))
	}
	r.Assets = nil
	r.Findings = make([]ctis.Finding, 200)
	for i := range r.Findings {
		r.Findings[i].Type = "web3"
	}
	if v, _ := c.Check(r, CheckOptions{MaxViolations: 5}); len(v) != 5 {
		t.Fatalf("cap on findings: %d", len(v))
	}
}

func TestCheckNilAndEmpty(t *testing.T) {
	c := mustLookup(t, "sca.deps@1")
	if v, err := c.Check(nil, CheckOptions{}); v != nil || err != nil {
		t.Fatal("nil report")
	}
	if v, _ := c.Check(&ctis.Report{}, CheckOptions{}); len(v) != 0 {
		t.Fatal("an empty result conforms")
	}
	r := &ctis.Report{Dependencies: []ctis.Dependency{{Name: "lodash"}}}
	v, _ := c.Check(r, CheckOptions{})
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
