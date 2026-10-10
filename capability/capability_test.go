package capability

import (
	"flag"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

var update = flag.Bool("update", false, "rewrite docs/capabilities.md")

// The capability ids of the platform's scan stage catalog (routed and
// planned). The taxonomy must keep every one of them: a stored workflow
// names them. Copied until the platform reads this package.
var platformIDs = []string{
	"discover.subdomains", "resolve.dns", "scan.ports", "probe.http", "crawl.web",
	"vuln.templates", "dast.web", "secrets.code", "sast.code", "sca.deps",
	"iac.misconfig", "container.image", "network_va.connector",
	"intel.passive", "check.takeover", "detect.services", "fingerprint.tech",
	"check.tls", "capture.screenshot", "host.credentialed", "cloud.posture", "verify.finding",
	"lookup.rdap", "lookup.asn",
}

func TestEmbeddedTaxonomyLoads(t *testing.T) {
	if _, err := load(taxonomyJSON); err != nil {
		t.Fatal(err)
	}
	if got := len(All()); got != 32 {
		t.Fatalf("capabilities = %d, want 32 (28 v1 + 4 later)", got)
	}
}

func TestPlatformIDsKept(t *testing.T) {
	for _, id := range platformIDs {
		c, ok := Lookup(id + "@1")
		if !ok {
			t.Errorf("%s@1 missing", id)
			continue
		}
		if c.Status == StatusLater {
			t.Errorf("%s: a platform capability cannot be 'later'", id)
		}
	}
}

func TestRoutedParamsMatchPlatform(t *testing.T) {
	// The standard params the platform already exposes for routed stages
	// stay, in order; a new param may only follow them (additive).
	want := map[string][]string{
		"discover.subdomains":  {"sources", "recursive", "max_results"},
		"resolve.dns":          {"record_types", "wildcard_filter"},
		"scan.ports":           {"ports", "top_n", "protocol", "rate"},
		"probe.http":           {"ports", "follow_redirects", "tech_detect", "tls_grab"},
		"crawl.web":            {"depth", "js_parse", "max_urls"},
		"vuln.templates":       {"severity", "tags", "exclude_tags", "rate"},
		"dast.web":             {"profile", "max_duration_minutes"},
		"secrets.code":         {"history"},
		"sast.code":            {"languages"},
		"sca.deps":             {"dev_deps"},
		"iac.misconfig":        {"frameworks"},
		"container.image":      {"os_pkgs"},
		"network_va.connector": {"policy"},
	}
	for id, names := range want {
		c, _ := Lookup(id)
		var got []string
		for _, p := range c.Params {
			got = append(got, p.Name)
		}
		if len(got) < len(names) || !reflect.DeepEqual(got[:len(names)], names) {
			t.Errorf("%s params = %v, want %v", id, got, names)
		}
	}
}

func TestTierFloors(t *testing.T) {
	want := map[string]int{
		"discover.subdomains": 0, "resolve.dns": 0, "scan.ports": 1, "probe.http": 1,
		"crawl.web": 1, "vuln.templates": 1, "dast.web": 2, "secrets.code": 0,
		"sast.code": 0, "sca.deps": 0, "iac.misconfig": 0, "container.image": 0,
		"network_va.connector": 1, "simulate.attack": 2, "lookup.rdap": 0, "lookup.asn": 0,
	}
	for id, tier := range want {
		c, _ := Lookup(id)
		if c.TierFloor != tier {
			t.Errorf("%s tier floor = %d, want %d", id, c.TierFloor, tier)
		}
	}
}

func TestParseRefAndLookup(t *testing.T) {
	cases := []struct {
		ref   string
		id    string
		major int
		ok    bool
	}{
		{"scan.ports@1", "scan.ports", 1, true},
		{"scan.ports", "scan.ports", 0, true},
		{"network_va.connector@1", "network_va.connector", 1, true},
		{"scan.ports@0", "", 0, false},
		{"scan.ports@01", "", 0, false},
		{"scan.ports@1000", "", 0, false},
		{"Scan.Ports@1", "", 0, false},
		{" scan.ports@1", "", 0, false},
		{"scan", "", 0, false},
		{"scan..ports", "", 0, false},
		{"scan.ports@1\n", "", 0, false},
		{"", "", 0, false},
	}
	for _, tc := range cases {
		id, major, ok := ParseRef(tc.ref)
		if id != tc.id || major != tc.major || ok != tc.ok {
			t.Errorf("ParseRef(%q) = %q,%d,%v want %q,%d,%v", tc.ref, id, major, ok, tc.id, tc.major, tc.ok)
		}
	}
	if _, ok := Lookup("scan.ports@2"); ok {
		t.Error("a major that does not exist must not resolve")
	}
	if _, ok := Lookup("portscan"); ok {
		t.Error("a pre-taxonomy word must not resolve")
	}
	if c, ok := Lookup("scan.ports"); !ok || c.Ref() != "scan.ports@1" {
		t.Errorf("Lookup without major = %q,%v", c.Ref(), ok)
	}
}

func TestLookupReturnsCopies(t *testing.T) {
	c, _ := Lookup("scan.ports@1")
	c.Params[0].Name = "mutated"
	*c.Params[1].Max = 1
	c.InPorts[0] = "x"
	c.Outputs[0].Paths[0] = "x"
	again, _ := Lookup("scan.ports@1")
	if again.Params[0].Name == "mutated" || *again.Params[1].Max == 1 || again.InPorts[0] == "x" || again.Outputs[0].Paths[0] == "x" {
		t.Fatal("Lookup leaked the shared taxonomy")
	}
	p := PortTypes()
	p[0].Carries[0] = "x"
	if PortTypes()[0].Carries[0] == "x" {
		t.Fatal("PortTypes leaked the shared taxonomy")
	}
}

func TestAcceptsAndMayEmit(t *testing.T) {
	ports, _ := Lookup("scan.ports@1")
	for _, at := range []string{"domain", "subdomain", "ip_address", "host"} {
		if !ports.Accepts(at) {
			t.Errorf("scan.ports should accept %s", at)
		}
	}
	if ports.Accepts("repository") || ports.Accepts("http_service") {
		t.Error("scan.ports accepts a type no input port carries")
	}
	for kind, want := range map[string]bool{
		"asset:open_port": true, "asset:ip_address": true, "asset:host": true,
		"asset:domain":      true, // re-observed input
		"asset:certificate": false, "asset:repository": false, "asset:": false,
		"finding:vulnerability": false, "dependency": false, "bogus": false,
	} {
		if got := ports.MayEmit(kind); got != want {
			t.Errorf("scan.ports MayEmit(%q) = %v", kind, got)
		}
	}
	probe, _ := Lookup("probe.http")
	if !probe.MayEmit("asset:certificate") {
		t.Error("probe.http emits certificates")
	}
	secrets, _ := Lookup("secrets.code")
	if !secrets.MayEmit("finding:secret") || secrets.MayEmit("finding:vulnerability") || secrets.MayEmit("finding:") {
		t.Error("secrets.code finding types")
	}
	vt, _ := Lookup("vuln.templates")
	if !vt.MayEmit("finding:vulnerability") || vt.MayEmit("finding:") {
		t.Error("vuln.templates findings")
	}
	sca, _ := Lookup("sca.deps")
	if !sca.MayEmit("dependency") || sca.MayEmit("dependency:x") {
		t.Error("sca.deps dependencies")
	}
	imp, _ := Lookup("import.file")
	if !imp.MayEmit("asset:repository") {
		t.Error("import.file emits any asset type")
	}
}

func TestPhasesAndCTEMStage(t *testing.T) {
	if len(Phases()) != 5 {
		t.Fatal("five phases")
	}
	vf, _ := Lookup("verify.finding")
	if vf.CTEMStage() != "validation" || !vf.CrossCutting {
		t.Error("verify.finding is a cross-cutting validation act")
	}
	sd, _ := Lookup("discover.subdomains")
	if sd.CTEMStage() != "discovery" || !sd.Runnable() {
		t.Error("discover.subdomains")
	}
	if _, ok := LookupPhase("bogus"); ok {
		t.Error("unknown phase")
	}
	if (Capability{Phase: "bogus"}).CTEMStage() != "" {
		t.Error("unknown phase has no stage")
	}
	if len(Routed()) == 0 {
		t.Error("routed")
	}
	if _, ok := LookupPortType("bogus"); ok {
		t.Error("unknown port type")
	}
	if p, ok := ports(t).Param("rate"); !ok || *p.Max != 100000 {
		t.Error("rate param")
	}
	if _, ok := ports(t).Param("nope"); ok {
		t.Error("unknown param")
	}
	if got := ports(t).Shapes(); !reflect.DeepEqual(got, []string{"open_port_assets", "ip_ports"}) {
		t.Errorf("shapes = %v", got)
	}
}

func ports(t *testing.T) Capability {
	t.Helper()
	c, ok := Lookup("scan.ports@1")
	if !ok {
		t.Fatal("scan.ports")
	}
	return c
}

func TestFrameworkIDsAreWellFormed(t *testing.T) {
	// load already validates; this proves the patterns refuse bad ids.
	for _, bad := range []string{"T159", "T1595.1", "t1595", "TA0043", "T1595.001;"} {
		if attackRE.MatchString(bad) {
			t.Errorf("ATT&CK pattern accepted %q", bad)
		}
	}
	for _, bad := range []string{"D3-", "d3-AI", "D3-AI1"} {
		if d3fendRE.MatchString(bad) {
			t.Errorf("D3FEND pattern accepted %q", bad)
		}
	}
	if capecRE.MatchString("CAPEC-") {
		t.Error("CAPEC pattern")
	}
}

func TestJSONIsACopy(t *testing.T) {
	j := JSON()
	j[0] = 'x'
	if JSON()[0] == 'x' {
		t.Fatal("JSON leaked the embedded bytes")
	}
}

func TestMarkdownIsCurrent(t *testing.T) {
	const path = "../docs/capabilities.md"
	got := Markdown()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatal("docs/capabilities.md is stale: run go test ./capability -run TestMarkdownIsCurrent -update")
	}
	for _, c := range All() {
		if !strings.Contains(got, "### "+c.Ref()) {
			t.Errorf("%s not documented", c.Ref())
		}
	}
}

func TestEveryAssetTypeInPortsIsCTIS(t *testing.T) {
	known := map[string]bool{}
	for _, at := range ctis.AllAssetTypes() {
		known[string(at)] = true
	}
	var unknown []string
	for _, p := range PortTypes() {
		for _, c := range p.Carries {
			if !known[c] {
				unknown = append(unknown, c)
			}
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Fatalf("unknown CTIS asset types: %v", unknown)
	}
}
