package secretref

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

type keyCase struct {
	Name     string   `json:"name"`
	Provider string   `json:"provider"`
	Key      string   `json:"key"`
	Code     string   `json:"code"`
	Audience []string `json:"audience"`
}

func loadKeyCases(t *testing.T) []keyCase {
	t.Helper()
	b, err := os.ReadFile("testdata/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []keyCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

func TestProviderKeyGoldens(t *testing.T) {
	for _, c := range loadKeyCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			p, ok := LookupProvider(c.Provider)
			if !ok {
				t.Fatalf("no provider %s", c.Provider)
			}
			key := c.Key
			if key == "LONG" {
				key = strings.Repeat("a", MaxKeyLen+1)
			}
			aud, err := p.Audience(key)
			if c.Code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !slices.Equal(aud, c.Audience) {
					t.Fatalf("audience %v, want %v", aud, c.Audience)
				}
				return
			}
			var ke *KeyError
			if !errors.As(err, &ke) || ke.Code != c.Code {
				t.Fatalf("error %v, want code %s", err, c.Code)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("a key error must match ErrInvalid")
			}
			if len(c.Key) >= 8 && strings.Contains(err.Error(), c.Key) {
				t.Fatal("the error repeats the key")
			}
		})
	}
}

func TestRegistry(t *testing.T) {
	ps := Providers()
	if len(ps) == 0 {
		t.Fatal("empty registry")
	}
	for i, p := range ps {
		if i > 0 && ps[i-1].ID >= p.ID {
			t.Fatal("providers are not ordered by id")
		}
		if (p.Endpoint == "") == (len(p.Hosts) == 0) {
			t.Fatalf("%s: a provider has fixed hosts exactly when its key names no endpoint", p.ID)
		}
		if !slices.Contains(ProvidersForTool("subfinder"), p.ID) {
			t.Fatalf("%s: not a subfinder provider", p.ID)
		}
	}
	// The registry is a copy: changing it does not change the next answer.
	ps[0].Hosts[0] = "evil.example"
	if q, _ := LookupProvider(ps[0].ID); slices.Contains(q.Hosts, "evil.example") {
		t.Fatal("Providers leaks the registry")
	}
	if _, ok := LookupProvider("nope"); ok {
		t.Fatal("unknown provider found")
	}
	if ProvidersForTool("nuclei") != nil {
		t.Fatal("nuclei queries no provider")
	}
	// The CT lookup tool (capability lookup.ct@1) takes only the optional
	// Cert Spotter key, sent only to api.certspotter.com.
	if got := ProvidersForTool("ctlog"); !slices.Equal(got, []string{"certspotter"}) {
		t.Fatalf("ctlog providers = %v", got)
	}
	if p, _ := LookupProvider("certspotter"); !slices.Equal(p.Hosts, []string{"api.certspotter.com"}) {
		t.Fatalf("certspotter hosts = %v", p.Hosts)
	}
}

func TestLoadRegistryRefuses(t *testing.T) {
	cases := map[string]string{
		"version":       `{"version":2,"providers":[]}`,
		"bad id":        `{"version":1,"providers":[{"id":"Bad","display":"x","format":"key","hosts":["a.example"],"tools":["t"]}]}`,
		"repeated id":   `{"version":1,"providers":[{"id":"a","display":"x","format":"key","hosts":["a.example"],"tools":["t"]},{"id":"a","display":"x","format":"key","hosts":["a.example"],"tools":["t"]}]}`,
		"format":        `{"version":1,"providers":[{"id":"a","display":"x","format":"blob","hosts":["a.example"],"tools":["t"]}]}`,
		"pair no hint":  `{"version":1,"providers":[{"id":"a","display":"x","format":"pair","hosts":["a.example"],"tools":["t"]}]}`,
		"ip host":       `{"version":1,"providers":[{"id":"a","display":"x","format":"key","hosts":["10.0.0.1"],"tools":["t"]}]}`,
		"host port":     `{"version":1,"providers":[{"id":"a","display":"x","format":"key","hosts":["a.example:443"],"tools":["t"]}]}`,
		"no hosts":      `{"version":1,"providers":[{"id":"a","display":"x","format":"key","hosts":[],"tools":["t"]}]}`,
		"unanchored":    `{"version":1,"providers":[{"id":"a","display":"x","format":"pair","pair_hint":"H:K","hosts":[],"endpoint":"host","host_rule":"a\\.example","tools":["t"]}]}`,
		"rule on fixed": `{"version":1,"providers":[{"id":"a","display":"x","format":"key","hosts":["a.example"],"host_rule":"^a$","tools":["t"]}]}`,
		"no tool":       `{"version":1,"providers":[{"id":"a","display":"x","format":"key","hosts":["a.example"]}]}`,
	}
	for name, raw := range cases {
		if _, err := loadRegistry([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLast4(t *testing.T) {
	p, _ := LookupProvider("censys")
	if got := p.Last4("someusername:abcdefgh1234"); got != "1234" {
		t.Fatalf("last4 %q", got)
	}
	if got := p.Last4("someusername:abcdefgh123"); got != "" {
		t.Fatalf("a short secret part shows nothing, got %q", got)
	}
	if p.SecretPart("user:secretsecret") != "secretsecret" {
		t.Fatal("secret part of a pair is its last part")
	}
}

// FuzzProviderAudience: whatever a key is, an accepted key's audience is
// the provider's fixed hosts plus at most one host its rule accepts, every
// host a DNS name (never an address, a port or user information).
func FuzzProviderAudience(f *testing.F) {
	for _, c := range []keyCase{{Provider: "intelx", Key: "2.intelx.io:abcdefgh1234"}, {Provider: "redhuntlabs", Key: "https://devportal.redhuntlabs.com/x:abcdefgh1234"},
		{Provider: "zoomeyeapi", Key: "zoomeye.ai:abcdefgh1234"}, {Provider: "shodan", Key: "abcdefgh1234"}, {Provider: "censys", Key: "a:abcdefgh1234"}} {
		f.Add(c.Provider, c.Key)
	}
	f.Fuzz(func(t *testing.T, id, key string) {
		p, ok := LookupProvider(id)
		if !ok {
			return
		}
		aud, err := p.Audience(key)
		if err != nil {
			if strings.Contains(err.Error(), key) && len(key) >= MinSecretLen {
				t.Fatal("the error repeats the key")
			}
			return
		}
		if len(aud) > len(p.Hosts)+1 {
			t.Fatalf("audience %v", aud)
		}
		for _, h := range aud {
			if !hostPattern.MatchString(h) || strings.ContainsAny(h, ":@/[]") {
				t.Fatalf("audience host %q", h)
			}
			if _, err := netip.ParseAddr(h); err == nil {
				t.Fatalf("audience address %q", h)
			}
			if !slices.Contains(p.Hosts, h) && !p.hostAllowed(strings.TrimPrefix(h, p.HostPrefix)) {
				t.Fatalf("audience host %q outside the provider's rule", h)
			}
		}
	})
}
