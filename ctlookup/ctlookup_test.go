package ctlookup

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Example.COM.", "example.com"},
		{"\ta.example.org\n", "a.example.org"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
	} {
		in, want := c.in, c.want
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "com", "*.example.com", "%.example.com", "192.0.2.1/24", "https://example.com", "a..example.com", "-a.example.com", "exa mple.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := NormalizeDomain(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeDomain(%q) accepted", in)
		}
	}
}

func TestCheckInput(t *testing.T) {
	in, err := CheckInput(Input{Domain: "Example.com", After: " 123 "})
	if err != nil || in.Domain != "example.com" || in.After != "123" {
		t.Fatalf("CheckInput = %+v, %v", in, err)
	}
	for _, bad := range []Input{{Domain: "example.com", After: strings.Repeat("1", MaxCursorLength+1)}, {Domain: "example.com", After: "1\n2"}, {Domain: "x"}} {
		if _, err := CheckInput(bad); err == nil {
			t.Errorf("CheckInput(%+v) accepted", bad)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	const d = "example.com"
	ok := map[string]string{
		"example.com":        "example.com",
		"*.example.com":      "*.example.com",
		"WWW.Example.com.":   "www.example.com",
		"*.DEV.example.com.": "*.dev.example.com",
		"_dmarc.example.com": "_dmarc.example.com",
	}
	for in, want := range ok {
		if got, k := NormalizeName(in, d); !k || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v; want %q", in, got, k, want)
		}
	}
	for _, in := range []string{
		"example.org", "notexample.com", "example.com.evil.test", "a.*.example.com", "*.*.example.com",
		"user@example.com", "192.0.2.1", "", "*", "exa mple.com", "a\nb.example.com",
	} {
		if got, k := NormalizeName(in, d); k {
			t.Errorf("NormalizeName(%q) = %q accepted", in, got)
		}
	}
}

// A sensor may answer with names of other domains (a compromised sensor, or
// a source answering for more than asked): they never pass.
func TestValidateBindsNamesToTheDomain(t *testing.T) {
	out := Output{
		Records: []Record{
			{Source: SourceCRTSH, EntryID: "1", DNSNames: []string{"*.Example.com", "www.example.com", "victim.example.org", "www.example.com"},
				Issuer: "C=US, O=Example CA", Serial: "0a", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2026-04-01T00:00:00+07:00"},
			{Source: SourceCertSpotter, EntryID: "2", DNSNames: []string{"other.example.net"}},
			{Source: SourceCRTSH, EntryID: "1", DNSNames: []string{"dup.example.com"}},
			{Source: SourceCRTSH, EntryID: "3", DNSNames: []string{"api.example.com"}, NotAfter: "2026-13-01"},
		},
		SourceStatus: []SourceStatus{{Source: SourceCRTSH, State: StateOK}, {Source: SourceCertSpotter, State: StateRateLimited, RetryAfterS: 60}},
	}
	clean, rep, err := Validate("example.com", out)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Records) != 2 {
		t.Fatalf("records %+v", clean.Records)
	}
	if got := clean.Records[0].DNSNames; !slices.Equal(got, []string{"*.example.com", "www.example.com"}) {
		t.Errorf("names %v", got)
	}
	if clean.Records[0].NotAfter != "2026-03-31T17:00:00Z" {
		t.Errorf("not_after %q", clean.Records[0].NotAfter)
	}
	if clean.Records[1].NotAfter != "" || rep.ClearedFields != 1 {
		t.Errorf("bad time kept: %q, %+v", clean.Records[1].NotAfter, rep)
	}
	if rep.DroppedNames != 2 || rep.DroppedRecords != 2 {
		t.Errorf("report %+v", rep)
	}
	if len(clean.SourceStatus) != 2 {
		t.Errorf("status %+v", clean.SourceStatus)
	}
}

func TestWildcard(t *testing.T) {
	if h, ok := Wildcard("*.a.example.com"); !ok || h != "a.example.com" {
		t.Fatalf("Wildcard = %q, %v", h, ok)
	}
	if _, ok := Wildcard("a.example.com"); ok {
		t.Fatal("plain name read as a wildcard")
	}
}

func TestValidateRefusesBrokenOutputs(t *testing.T) {
	many := make([]Record, MaxRecords+1)
	for i := range many {
		many[i] = Record{Source: SourceCRTSH, DNSNames: []string{"example.com"}}
	}
	names := make([]string, MaxNamesPerRecord+1)
	for i := range names {
		names[i] = "example.com"
	}
	for name, out := range map[string]Output{
		"too many records":  {Records: many},
		"too many names":    {Records: []Record{{Source: SourceCRTSH, DNSNames: names}}},
		"unknown source":    {Records: []Record{{Source: "evil", DNSNames: []string{"example.com"}}}},
		"unknown state":     {SourceStatus: []SourceStatus{{Source: SourceCRTSH, State: "fine"}}},
		"status twice":      {SourceStatus: []SourceStatus{{Source: SourceCRTSH, State: StateOK}, {Source: SourceCRTSH, State: StateOK}}},
		"status of unknown": {SourceStatus: []SourceStatus{{Source: "x", State: StateOK}}},
		"negative wait":     {SourceStatus: []SourceStatus{{Source: SourceCRTSH, State: StateRateLimited, RetryAfterS: -1}}},
		"long wait":         {SourceStatus: []SourceStatus{{Source: SourceCRTSH, State: StateRateLimited, RetryAfterS: MaxRetryAfter + 1}}},
		"control in issuer": {Records: []Record{{Source: SourceCRTSH, DNSNames: []string{"example.com"}, Issuer: "a\x1b[31m"}}},
		"long serial":       {Records: []Record{{Source: SourceCRTSH, DNSNames: []string{"example.com"}, Serial: strings.Repeat("a", MaxFieldLength+1)}}},
	} {
		if _, _, err := Validate("example.com", out); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestValidateEmptyIsValid(t *testing.T) {
	clean, _, err := Validate("example.com", Output{})
	if err != nil || clean.Records == nil || clean.SourceStatus == nil {
		t.Fatalf("Validate(empty) = %+v, %v", clean, err)
	}
}
