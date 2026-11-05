// Package webpath is the one reading of a web request path shared by the
// platform and the sensor: how a server sees a path (CleanPath), whether a
// path falls under an excluded path (Denied) or an allowed prefix (Under),
// and whether a path names a state-changing action (Destructive).
//
// The platform plans path discovery and filters candidate lists with these
// functions, and the sensor's web scope refuses requests with the same ones,
// so a candidate the platform keeps is never one the sensor would refuse for
// a different reason, and an exclusion can never be read two ways.
package webpath

import (
	"errors"
	"net/url"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Errors of CleanPath.
var (
	ErrEncodedSeparator = errors.New("encoded separator in the path")
	ErrBadEscape        = errors.New("invalid percent-encoding in the path")
	ErrControl          = errors.New("control character in the path")
	ErrDotParams        = errors.New("dot segment with parameters in the path")
)

// CleanPath is the path a server sees for an escaped request path:
// percent-decoded, backslashes read as slashes, dot segments resolved, never
// empty, a trailing slash kept. A path with an encoded slash, backslash or
// NUL, a control character, or a dot segment with parameters ("..;") is
// refused: servers disagree on it.
func CleanPath(escaped string) (string, error) {
	if escaped == "" {
		return "/", nil
	}
	lower := strings.ToLower(escaped)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return "", ErrEncodedSeparator
	}
	dec, err := unescape(escaped)
	if err != nil {
		return "", ErrBadEscape
	}
	if strings.ContainsFunc(dec, isControl) {
		return "", ErrControl
	}
	dec = strings.ReplaceAll(dec, "\\", "/")
	for _, seg := range strings.Split(dec, "/") {
		if base, _, ok := strings.Cut(seg, ";"); ok && (base == "." || base == "..") {
			return "", ErrDotParams
		}
	}
	return clean(dec), nil
}

// Readings are the paths a server may act on for a clean path: the path
// itself; when a segment has parameters (";jsessionid=..."), the path
// without them; and when the path still holds a percent-escape, the path a
// server that decodes twice sees ("/%2561dmin" reaches it as "/admin"). A
// check must pass for every reading.
func Readings(p string) []string {
	out := []string{p}
	if dec, err := unescape(p); err == nil && dec != p && !strings.ContainsFunc(dec, isControl) {
		out = append(out, clean(strings.ReplaceAll(dec, "\\", "/")))
	}
	for _, v := range out {
		if strings.Contains(v, ";") {
			segs := strings.Split(v, "/")
			for i, seg := range segs {
				segs[i], _, _ = strings.Cut(seg, ";")
			}
			if w := clean(strings.Join(segs, "/")); !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
	}
	return out
}

// Denied returns the first deny path that a clean path falls under, in any
// reading. A deny path matches every path that starts with it, ignoring
// case: over-blocking is the safe side ("/admin" also denies "/Admin" and
// "/administrator"). A segment "*" of a deny path matches any one segment
// ("/tenants/*/admin" denies "/tenants/acme/admin/x"), as the platform's
// path exclusions read it.
//
// Both sides are compared in the form a lenient server reads them: case
// folded to ASCII (a letter whose case folding includes an ASCII letter,
// such as U+017F for "s" or U+212A for "k", is that letter), and trailing
// dots and spaces of a segment dropped ("/admin./x" is "/admin/x" to a
// Windows server). A deny path is taken both as written and percent-decoded
// (an exclusion stored as "/files/My%20Docs" denies "/files/My Docs/a.bak"),
// so a deny list of either form holds.
func Denied(p string, deny []string) (string, bool) {
	keys := make([]string, 0, 3)
	for _, v := range Readings(p) {
		keys = append(keys, matchKey(v))
	}
	for _, d := range deny {
		for _, dk := range denyKeys(d) {
			for _, k := range keys {
				if deniedBy(k, dk) {
					return d, true
				}
			}
		}
	}
	return "", false
}

// CleanDeny is the stored form of a deny path: percent-decoded and cleaned
// as CleanPath reads a request ("/files/My%20Docs" is "/files/My Docs"), so
// it compares with the path a server sees. A deny path CleanPath refuses is
// an error; a trailing slash is kept.
func CleanDeny(d string) (string, error) {
	if d == "" || d[0] != '/' {
		return "", errors.New("a deny path must be absolute")
	}
	dec, err := unescape(d)
	if err != nil {
		return "", ErrBadEscape
	}
	if HasDotSegment(strings.ReplaceAll(dec, "\\", "/")) {
		return "", errors.New("dot segment in the deny path")
	}
	return CleanPath(d)
}

// ErrCandidate is the error of CheckCandidate.
var ErrCandidate = errors.New("candidate path is not plain ASCII")

// CheckCandidate checks a guessed candidate path (escaped) before it is
// requested: CleanPath must accept it, and it may hold neither an escaped
// percent sign ("%25", read twice by some servers) nor a byte outside
// printable ASCII, raw or decoded (servers fold such letters to ASCII in
// different ways). A guess list never needs either.
func CheckCandidate(escaped string) error {
	if strings.Contains(strings.ToLower(escaped), "%25") {
		return ErrCandidate
	}
	c, err := CleanPath(escaped)
	if err != nil {
		return err
	}
	for i := 0; i < len(escaped); i++ {
		if escaped[i] >= 0x80 {
			return ErrCandidate
		}
	}
	for i := 0; i < len(c); i++ {
		if c[i] >= 0x80 {
			return ErrCandidate
		}
	}
	return nil
}

// denyKeys are the match keys of a deny path: as written (backslashes as
// slashes and empty segments removed, as in a clean request path) and, when it decodes to
// another path, decoded and cleaned.
func denyKeys(d string) []string {
	if d == "" {
		return nil
	}
	written := d
	if w := strings.ReplaceAll(d, "\\", "/"); !HasDotSegment(w) {
		written = clean(w)
	}
	keys := []string{matchKey(written)}
	if dec, err := unescape(d); err == nil && dec != d && !strings.ContainsFunc(dec, isControl) {
		dec = strings.ReplaceAll(dec, "\\", "/")
		if !HasDotSegment(dec) {
			if k := matchKey(clean(dec)); k != keys[0] {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

// deniedBy reports whether the match key of a path falls under the match key
// of a deny path: a string prefix, or segment by segment when the deny path
// has a "*" segment (the last segment is then a prefix of the path's
// segment, as the plain form is a string prefix).
func deniedBy(k, d string) bool {
	if !hasWildSegment(d) {
		return strings.HasPrefix(k, d)
	}
	ds := strings.Split(d, "/")
	ks := strings.Split(k, "/")
	if len(ks) < len(ds) {
		return false
	}
	for i := 1; i < len(ds); i++ {
		switch {
		case ds[i] == "*":
		case i == len(ds)-1:
			if !strings.HasPrefix(ks[i], ds[i]) {
				return false
			}
		case ks[i] != ds[i]:
			return false
		}
	}
	return true
}

func hasWildSegment(p string) bool {
	return slices.Contains(strings.Split(p, "/"), "*")
}

// matchKey is the form a path is compared in: case folded to ASCII and
// every segment without trailing dots and spaces.
func matchKey(p string) string {
	segs := strings.Split(foldASCII(p), "/")
	for i, s := range segs {
		if t := strings.TrimRight(s, ". "); t != "" {
			segs[i] = t
		}
	}
	return strings.Join(segs, "/")
}

// foldASCII lower-cases ASCII letters and maps a letter whose case folding
// includes an ASCII letter to that letter, lower-cased; any other letter is
// lower-cased.
func foldASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf {
			if 'A' <= r && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}
		for _, c := range []rune{unicode.ToLower(r), unicode.ToUpper(r)} {
			if c < utf8.RuneSelf && unicode.IsLetter(c) {
				return unicode.ToLower(c)
			}
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf {
				return unicode.ToLower(f)
			}
		}
		return unicode.ToLower(r)
	}, s)
}

// Under reports whether a clean path is the prefix or under it, at a segment
// boundary, in every reading. An empty prefix or "/" is every path.
func Under(p, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	for _, v := range Readings(p) {
		if prefix != "" && v != prefix && !strings.HasPrefix(v, prefix+"/") {
			return false
		}
	}
	return true
}

// DestructiveVerbs are the words that mark a path as a state-changing action
// a GET may still trigger (a logout link, "/admin/delete?id=1"). Discovery
// never requests such a path and a crawler never follows one.
var DestructiveVerbs = []string{
	"logout", "logoff", "signout", "delete", "remove", "destroy", "drop", "purge", "wipe",
	"reset", "shutdown", "restart", "reboot", "kill", "unsubscribe", "cancel", "revoke",
}

// exactOnly are the verbs that match only a whole word: as a word prefix
// they would block ordinary names ("dropdown", "killer", "wiper").
var exactOnly = map[string]bool{"drop": true, "kill": true, "wipe": true}

// Destructive reports whether a path (escaped or clean) names a
// state-changing action: a segment has a word that is one of
// DestructiveVerbs, or that starts with one ("deleteUser", "logout_all",
// "resetPassword"), or two adjacent words that join into one ("log-out",
// "sign_out"). Words are split on anything that is not a letter or a digit,
// and on a lower-to-upper case change. Over-blocking is the safe side.
func Destructive(p string) bool {
	if dec, err := unescape(p); err == nil {
		p = dec
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		words := splitWords(seg)
		for i, w := range words {
			if isVerb(w, true) || (i+1 < len(words) && isVerb(w+words[i+1], false)) {
				return true
			}
		}
	}
	return false
}

func isVerb(w string, prefix bool) bool {
	for _, v := range DestructiveVerbs {
		if w == v || (prefix && !exactOnly[v] && strings.HasPrefix(w, v)) {
			return true
		}
	}
	return false
}

// splitWords splits a segment into lowercase words.
func splitWords(seg string) []string {
	var words []string
	var cur []rune
	var prevLower bool
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range seg {
		switch {
		case r >= 'A' && r <= 'Z':
			if prevLower {
				flush()
			}
			cur = append(cur, r)
			prevLower = false
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			cur = append(cur, r)
			prevLower = true
		default:
			flush()
			prevLower = false
		}
	}
	flush()
	return words
}

// unescape percent-decodes a path as net/url does for a path ('+' stays
// '+').
func unescape(s string) (string, error) { return url.PathUnescape(s) }

func clean(dec string) string {
	trailing := strings.HasSuffix(dec, "/")
	c := path.Clean("/" + dec)
	if trailing && c != "/" {
		c += "/"
	}
	return c
}

// HasDotSegment reports whether a path has a "." or ".." segment.
func HasDotSegment(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(s string) bool { return s == "." || s == ".." })
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }
