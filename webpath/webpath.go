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
// itself and, when a segment has parameters (";jsessionid=..."), the path
// without them. A check must pass for every reading.
func Readings(p string) []string {
	if !strings.Contains(p, ";") {
		return []string{p}
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i], _, _ = strings.Cut(seg, ";")
	}
	return []string{p, clean(strings.Join(segs, "/"))}
}

// Denied returns the first deny path that a clean path falls under, in any
// reading. A deny path matches every path that starts with it, ignoring
// case: over-blocking is the safe side ("/admin" also denies "/Admin" and
// "/administrator").
func Denied(p string, deny []string) (string, bool) {
	for _, v := range Readings(p) {
		lower := strings.ToLower(v)
		for _, d := range deny {
			if d != "" && strings.HasPrefix(lower, strings.ToLower(d)) {
				return d, true
			}
		}
	}
	return "", false
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
