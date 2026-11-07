package identity

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func list(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("Mozilla/5.0 (test %d)", i)
	}
	return out
}

func TestCheckUserAgent(t *testing.T) {
	ok := []string{"openctemio-sensor/1.0", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0", strings.Repeat("a", MaxUserAgentLen)}
	for _, ua := range ok {
		if err := CheckUserAgent(ua); err != nil {
			t.Errorf("CheckUserAgent(%q) = %v", ua, err)
		}
	}
	bad := []string{"", strings.Repeat("a", MaxUserAgentLen+1), "a\r\nX-Injected: 1", "a\nb", "a\x00b", "tab\there", "café", " lead", "trail "}
	for _, ua := range bad {
		if err := CheckUserAgent(ua); !errors.Is(err, ErrInvalid) {
			t.Errorf("CheckUserAgent(%q) = %v, want ErrInvalid", ua, err)
		}
	}
}

func TestCheckUserAgents(t *testing.T) {
	if err := CheckUserAgents(nil); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if err := CheckUserAgents(list(MaxUserAgents)); err != nil {
		t.Fatalf("%d values: %v", MaxUserAgents, err)
	}
	if err := CheckUserAgents(list(MaxUserAgents + 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%d values: %v, want ErrInvalid", MaxUserAgents+1, err)
	}
	if err := CheckUserAgents([]string{"a", "b", "a"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate: %v, want ErrInvalid", err)
	}
	if err := CheckUserAgents([]string{"a", "b\r\nHost: example.org"}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "User-Agent 2") {
		t.Fatalf("CR/LF in the second value: %v", err)
	}
}

func TestCheckKey(t *testing.T) {
	if err := CheckKey(""); err != nil {
		t.Fatal(err)
	}
	if err := CheckKey("0b7c6a2e-4f0e-4d43-9a54-3f0b2b0c1d11"); err != nil {
		t.Fatal(err)
	}
	if err := CheckKey(strings.Repeat("k", MaxKeyLen+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long key: %v", err)
	}
	if err := CheckKey("run\n1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control character: %v", err)
	}
}

func TestCanonicalHost(t *testing.T) {
	cases := map[string]string{
		"www.example.com":                     "www.example.com",
		"https://WWW.Example.com.:8443/a?b=c": "www.example.com",
		"http://www.example.com":              "www.example.com",
		"www.example.com:80":                  "www.example.com",
		"www.example.com/path":                "www.example.com",
		"[2001:db8::1]:443":                   "2001:db8::1",
		"https://[2001:DB8::1]/":              "2001:db8::1",
		"203.0.113.7":                         "203.0.113.7",
		"  App.Example.ORG  ":                 "app.example.org",
	}
	for in, want := range cases {
		if got := CanonicalHost(in); got != want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// One run keeps one value per host, whatever the port, scheme or case of
// the host in a request.
func TestSelectIsSticky(t *testing.T) {
	l := list(MaxUserAgents)
	key := "run-1"
	want := SelectUserAgent(key, "www.example.com", l)
	for _, h := range []string{"https://www.example.com/login", "WWW.EXAMPLE.COM:8443", "http://www.example.com.", "www.example.com"} {
		for range 3 {
			if got := SelectUserAgent(key, h, l); got != want {
				t.Fatalf("SelectUserAgent(%q, %q) = %q, want %q", key, h, got, want)
			}
		}
	}
}

// The function is a fixed rule: the platform shows the value a host gets
// and the sensor sends it, so the result must never change silently.
func TestSelectIsStable(t *testing.T) {
	l := list(MaxUserAgents)
	golden := map[[2]string]int{}
	for _, k := range []string{"run-1", "run-2"} {
		for _, h := range []string{"www.example.com", "api.example.com"} {
			golden[[2]string{k, h}] = SelectIndex(k, h, len(l))
		}
	}
	// Recomputing gives the same indexes (no hidden state, no randomness).
	for kh, i := range golden {
		if got := SelectIndex(kh[0], kh[1], len(l)); got != i {
			t.Fatalf("SelectIndex(%q, %q) changed: %d then %d", kh[0], kh[1], i, got)
		}
	}
	if got := SelectIndex("run-1", "www.example.com", 200); got != pinnedIndex {
		t.Fatalf("SelectIndex(run-1, www.example.com, 200) = %d, the rule pinned %d: a new rule needs a new label", got, pinnedIndex)
	}
}

// pinnedIndex is the index the v1 rule gives ("run-1", "www.example.com",
// 200). It changes only with selectionLabel.
const pinnedIndex = 98

func TestSelectSpreadsEvenly(t *testing.T) {
	const n, hosts = 20, 20000
	counts := make([]int, n)
	for i := range hosts {
		counts[SelectIndex("run-1", fmt.Sprintf("h%d.example.com", i), n)]++
	}
	// Chi-square with n-1 = 19 degrees of freedom: 43.8 is the 0.001
	// critical value.
	exp := float64(hosts) / n
	chi := 0.0
	for _, c := range counts {
		d := float64(c) - exp
		chi += d * d / exp
	}
	if chi > 43.8 {
		t.Fatalf("hosts do not spread evenly over %d values: chi-square %.1f, counts %v", n, chi, counts)
	}
	// The same host spreads over runs too.
	counts = make([]int, n)
	for i := range hosts {
		counts[SelectIndex(fmt.Sprintf("run-%d", i), "www.example.com", n)]++
	}
	chi = 0
	for _, c := range counts {
		d := float64(c) - exp
		chi += d * d / exp
	}
	if chi > 43.8 {
		t.Fatalf("runs do not spread evenly over %d values: chi-square %.1f, counts %v", n, chi, counts)
	}
}

func TestSelectEdges(t *testing.T) {
	if got := SelectUserAgent("k", "www.example.com", nil); got != "" {
		t.Fatalf("empty list: %q", got)
	}
	if got := SelectIndex("k", "www.example.com", 0); got != -1 {
		t.Fatalf("n=0: %d", got)
	}
	if got := SelectUserAgent("k", "www.example.com", []string{"only"}); got != "only" {
		t.Fatalf("one value: %q", got)
	}
	// Another run key moves at least some hosts (the key takes part).
	l := list(50)
	moved := 0
	for i := range 100 {
		h := fmt.Sprintf("h%d.example.com", i)
		if SelectUserAgent("run-a", h, l) != SelectUserAgent("run-b", h, l) {
			moved++
		}
	}
	if moved < 80 {
		t.Fatalf("only %d of 100 hosts change value between two runs", moved)
	}
}
