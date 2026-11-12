// Package ctlookup is the contract of capability lookup.ct@1: a Certificate
// Transparency lookup for one root domain, run by a platform-owned sensor on
// behalf of the platform, which makes no request to a CT source itself.
//
// The act is passive (tier 0): the sensor asks public CT search services
// (crt.sh first, then Cert Spotter) which certificates name the domain or a
// name under it. No packet reaches the domain's own hosts.
//
// The answer is not a CTIS document. It is the typed Output below, returned
// as the result of one lookup job. The sensor builds it and the platform
// reads it with the same rules (Validate), so both sides agree on what a
// valid answer is, and the platform never trusts the sensor's copy:
//
//   - every name must be the queried domain or a name under it; a wildcard
//     label ("*.") is removed; any other name is dropped and counted;
//   - names are lower-case ASCII host names (an IDN in its xn-- form);
//   - counts, lengths and the encoded size are bounded;
//   - a failure of a CT source is a SourceStatus entry (rate_limited,
//     unavailable, too_large), never a failed lookup.
//
// Stability: v1. Additive optional fields only before 1.0.
package ctlookup

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Capability is the capability a sensor reports when it serves CT lookups.
const Capability = "lookup.ct@1"

// Tool is the name of the built-in tool that implements the capability.
const Tool = "ctlog"

// Source names.
const (
	SourceCRTSH       = "crt.sh"
	SourceCertSpotter = "certspotter"
)

// VendorHosts are the only hosts a CT lookup may contact.
var VendorHosts = []string{"crt.sh", "api.certspotter.com"}

// ProviderSlot is the provider key slot (secretref providers registry) of
// the optional Cert Spotter key.
const ProviderSlot = "certspotter"

// Source states.
const (
	// StateOK: the source answered; its records are in the output.
	StateOK = "ok"
	// StateRateLimited: the source answered 429 (or asked to wait).
	StateRateLimited = "rate_limited"
	// StateUnavailable: the source failed (5xx, timeout, network, bad
	// answer) after its retries.
	StateUnavailable = "unavailable"
	// StateTooLarge: the source's answer was over the size cap. Nothing
	// of it is used: a truncated list would read as names that vanished.
	StateTooLarge = "too_large"
)

// Bounds of one answer.
const (
	// MaxRecords is the most certificate records in one output.
	MaxRecords = 20000
	// MaxNamesPerRecord is the most names one record carries.
	MaxNamesPerRecord = 1000
	// MaxNameLength is the longest host name (RFC 1035).
	MaxNameLength = 253
	// MaxFieldLength bounds issuer, serial and entry id.
	MaxFieldLength = 512
	// MaxOutputBytes is the most bytes of an encoded output (JSON).
	MaxOutputBytes = 8 << 20
	// MaxRetryAfter is the longest wait a source status may ask for.
	MaxRetryAfter = 24 * 60 * 60
	// MaxCursorLength bounds the Cert Spotter cursor of an input.
	MaxCursorLength = 128
)

// Input is what one lookup asks.
type Input struct {
	// Domain is the root domain: the lookup covers it and every name under
	// it. Never a wildcard, an address or a URL.
	Domain string `json:"domain"`
	// After is an optional Cert Spotter cursor (an issuance id): only
	// issuances after it are listed. crt.sh ignores it.
	After string `json:"after,omitempty"`
}

// Record is one certificate a CT source listed.
type Record struct {
	// Source is SourceCRTSH or SourceCertSpotter.
	Source string `json:"source"`
	// EntryID is the source's own id of the record (crt.sh certificate id,
	// Cert Spotter issuance id).
	EntryID string `json:"entry_id,omitempty"`
	// DNSNames are the names of the certificate under the queried domain,
	// normalised (lower case, no trailing dot, wildcard label removed),
	// each once.
	DNSNames []string `json:"dns_names"`
	// Issuer is the issuer's name as the source gives it.
	Issuer string `json:"issuer,omitempty"`
	// Serial is the certificate's serial number (crt.sh) or its SHA-256
	// (Cert Spotter), as the source gives it.
	Serial string `json:"serial,omitempty"`
	// NotBefore and NotAfter are the validity bounds, RFC 3339 in UTC
	// ("" when the source gave none or an unreadable one).
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

// SourceStatus is how one source answered.
type SourceStatus struct {
	Source string `json:"source"`
	State  string `json:"state"`
	// RetryAfterS is the wait the source asked for, in seconds (0: none).
	RetryAfterS int `json:"retry_after_s,omitempty"`
}

// Output is the answer of one lookup.
type Output struct {
	Records      []Record       `json:"records"`
	SourceStatus []SourceStatus `json:"source_status"`
}

// Report counts what Validate removed.
type Report struct {
	// DroppedNames are names outside the queried domain or not host names.
	DroppedNames int
	// DroppedRecords are records left with no name, or duplicates.
	DroppedRecords int
	// ClearedFields are validity bounds that were not RFC 3339 times.
	ClearedFields int
}

// ErrInvalid marks an input or an output that breaks the contract as a
// whole (not one name or record of it).
var ErrInvalid = errors.New("ctlookup: invalid")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// NormalizeDomain returns the canonical form of a root domain: lower-case
// ASCII labels without a trailing dot, at least two labels, no wildcard.
func NormalizeDomain(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if !isHostName(d) || !strings.Contains(d, ".") {
		return "", invalid("domain %q is not a host name with at least two labels", clip(s))
	}
	return d, nil
}

// CheckInput validates an input and returns it with its domain normalised.
func CheckInput(in Input) (Input, error) {
	d, err := NormalizeDomain(in.Domain)
	if err != nil {
		return Input{}, err
	}
	in.Domain = d
	in.After = strings.TrimSpace(in.After)
	if len(in.After) > MaxCursorLength || !printable(in.After) {
		return Input{}, invalid("after is not a cursor")
	}
	return in, nil
}

// NormalizeName returns name in canonical form when it is domain or a name
// under it: lower case, no trailing dot, and a leading wildcard label
// removed ("*.a.example.com" is "a.example.com"). ok is false for anything
// else (another domain, a name with a wildcard elsewhere, an address, an
// e-mail address). domain must be normalised (NormalizeDomain).
func NormalizeName(name, domain string) (string, bool) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	n = strings.TrimPrefix(n, "*.")
	if !isHostName(n) {
		return "", false
	}
	if n != domain && !strings.HasSuffix(n, "."+domain) {
		return "", false
	}
	return n, true
}

// Validate checks out against the contract for the lookup of domain
// (normalised) and returns the clean copy: names normalised and bounded to
// the domain, records with no name or repeated (same source and entry id)
// dropped, unreadable validity bounds cleared. An output that breaks the
// contract as a whole (too many records, an unknown source or state, a
// source listed twice) is an ErrInvalid error and nothing of it is used.
func Validate(domain string, out Output) (Output, Report, error) {
	var rep Report
	if len(out.Records) > MaxRecords {
		return Output{}, rep, invalid("%d records, at most %d", len(out.Records), MaxRecords)
	}
	if len(out.SourceStatus) > 2 {
		return Output{}, rep, invalid("%d source statuses, at most 2", len(out.SourceStatus))
	}
	clean := Output{Records: []Record{}, SourceStatus: []SourceStatus{}}
	seenSrc := map[string]bool{}
	for _, s := range out.SourceStatus {
		if !knownSource(s.Source) {
			return Output{}, rep, invalid("unknown source %q", clip(s.Source))
		}
		if seenSrc[s.Source] {
			return Output{}, rep, invalid("source %q listed twice", s.Source)
		}
		seenSrc[s.Source] = true
		switch s.State {
		case StateOK, StateRateLimited, StateUnavailable, StateTooLarge:
		default:
			return Output{}, rep, invalid("unknown state %q", clip(s.State))
		}
		if s.RetryAfterS < 0 || s.RetryAfterS > MaxRetryAfter {
			return Output{}, rep, invalid("retry_after_s %d outside 0..%d", s.RetryAfterS, MaxRetryAfter)
		}
		clean.SourceStatus = append(clean.SourceStatus, s)
	}
	seenRec := map[string]bool{}
	for _, r := range out.Records {
		if !knownSource(r.Source) {
			return Output{}, rep, invalid("record of unknown source %q", clip(r.Source))
		}
		if len(r.DNSNames) > MaxNamesPerRecord {
			return Output{}, rep, invalid("record with %d names, at most %d", len(r.DNSNames), MaxNamesPerRecord)
		}
		if len(r.EntryID) > MaxFieldLength || len(r.Issuer) > MaxFieldLength || len(r.Serial) > MaxFieldLength ||
			!printable(r.EntryID) || !printable(r.Issuer) || !printable(r.Serial) {
			return Output{}, rep, invalid("record field over %d bytes or not printable", MaxFieldLength)
		}
		names := make([]string, 0, len(r.DNSNames))
		for _, n := range r.DNSNames {
			c, ok := NormalizeName(n, domain)
			if !ok {
				rep.DroppedNames++
				continue
			}
			if !slices.Contains(names, c) {
				names = append(names, c)
			}
		}
		if len(names) == 0 {
			rep.DroppedRecords++
			continue
		}
		if r.EntryID != "" {
			k := r.Source + "\x00" + r.EntryID
			if seenRec[k] {
				rep.DroppedRecords++
				continue
			}
			seenRec[k] = true
		}
		r.DNSNames = names
		var cleared int
		r.NotBefore, cleared = normTime(r.NotBefore)
		rep.ClearedFields += cleared
		r.NotAfter, cleared = normTime(r.NotAfter)
		rep.ClearedFields += cleared
		clean.Records = append(clean.Records, r)
	}
	return clean, rep, nil
}

// FormatTime is the output form of a validity bound.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func normTime(s string) (string, int) {
	if s == "" {
		return "", 0
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", 1
	}
	return FormatTime(t), 0
}

func knownSource(s string) bool { return s == SourceCRTSH || s == SourceCertSpotter }

// isHostName: 1..253 bytes of dot-separated labels, each 1..63 bytes of
// a-z, 0-9, '-' and '_' (seen in CT names), not starting or ending with '-'.
func isHostName(s string) bool {
	if s == "" || len(s) > MaxNameLength {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// printable: no control characters (the fields reach logs and the console).
func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
