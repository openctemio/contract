// Package identity is the shared definition of how a scan's requests
// identify themselves to a target: the User-Agent values a layer may set,
// and how one value of a rotation list is chosen for a target host.
//
// The platform validates every layer (platform, organization, program) with
// these functions and the sensor validates the job it receives with the
// same ones, so a value one side accepts is one the other side sends. The
// selection is defined once here so the platform can show which User-Agent
// a host gets in a run and the sensor sends exactly that one.
//
// # User-Agent rotation
//
// A layer may give a list of up to MaxUserAgents values instead of one.
// SelectUserAgent picks one value per (key, host): the key is the scan run
// (the platform puts the run's id in the job), the host is the target host
// a request goes to. The choice is sticky: every request of one run to one
// host carries the same value, so a session never changes its fingerprint
// half way. Different runs and different hosts spread evenly over the list
// (HMAC-SHA-256 keyed by the run key, over the canonical host).
//
// Rotation never replaces the identification of a scan: identification
// headers and the identification query parameter are sent with every value
// of the list, and a job that requires identification is refused where a
// tool cannot carry it (see the sensor SDK's tool host).
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Bounds of the User-Agent values.
const (
	// MaxUserAgents is the most values a rotation list may hold.
	MaxUserAgents = 200
	// MaxUserAgentLen is the longest value, in bytes.
	MaxUserAgentLen = 256
	// MaxKeyLen is the longest selection key, in bytes.
	MaxKeyLen = 128
)

// selectionLabel separates the selection hash from every other use of the
// key. A new selection rule gets a new label.
const selectionLabel = "openctem.ua-select.v1"

// ErrInvalid is wrapped by every validation error of this package.
var ErrInvalid = errors.New("invalid identification")

// printableASCII reports whether s holds only 0x20-0x7e: no CR, LF, NUL or
// other control character can reach a request line.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// CheckUserAgent accepts a User-Agent of 1 to MaxUserAgentLen printable
// ASCII characters with no leading or trailing space.
func CheckUserAgent(ua string) error {
	switch {
	case ua == "":
		return fmt.Errorf("%w: a User-Agent is empty", ErrInvalid)
	case len(ua) > MaxUserAgentLen:
		return fmt.Errorf("%w: a User-Agent is longer than %d characters", ErrInvalid, MaxUserAgentLen)
	case !printableASCII(ua):
		return fmt.Errorf("%w: a User-Agent must be printable ASCII (no line break or other control character)", ErrInvalid)
	case strings.TrimSpace(ua) != ua:
		return fmt.Errorf("%w: a User-Agent starts or ends with a space", ErrInvalid)
	}
	return nil
}

// CheckUserAgents accepts a rotation list: at most MaxUserAgents values,
// each valid (CheckUserAgent), none twice. An empty list is valid (no
// rotation).
func CheckUserAgents(list []string) error {
	if len(list) > MaxUserAgents {
		return fmt.Errorf("%w: at most %d User-Agents, got %d", ErrInvalid, MaxUserAgents, len(list))
	}
	seen := make(map[string]bool, len(list))
	for i, ua := range list {
		if err := CheckUserAgent(ua); err != nil {
			return fmt.Errorf("User-Agent %d: %w", i+1, err)
		}
		if seen[ua] {
			return fmt.Errorf("%w: User-Agent %d is listed twice", ErrInvalid, i+1)
		}
		seen[ua] = true
	}
	return nil
}

// CheckKey accepts a selection key of at most MaxKeyLen printable ASCII
// characters ("" is valid: the selection then depends on the host alone).
func CheckKey(key string) error {
	if len(key) > MaxKeyLen || !printableASCII(key) {
		return fmt.Errorf("%w: the User-Agent selection key must be at most %d printable ASCII characters", ErrInvalid, MaxKeyLen)
	}
	return nil
}

// CanonicalHost is the host a selection is made for: the host of a URL, a
// host:port or a bare host, lower-cased, without a port, IPv6 brackets or a
// trailing dot. "https://WWW.Example.com.:8443/a" and "www.example.com"
// give the same host, so every port and scheme of a host gets one value.
func CanonicalHost(target string) string {
	s := strings.TrimSpace(target)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Host
		}
	} else if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	return strings.ToLower(s)
}

// SelectIndex returns the index in a list of n values that (key, host)
// gets: HMAC-SHA-256 keyed by key over the label and the canonical host,
// read as a big-endian uint64, modulo n. The bias of the modulo is below
// n/2^64. -1 when n < 1.
func SelectIndex(key, host string, n int) int {
	if n < 1 {
		return -1
	}
	if n == 1 {
		return 0
	}
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(selectionLabel))
	m.Write([]byte{0})
	m.Write([]byte(CanonicalHost(host)))
	sum := m.Sum(nil)
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(n))
}

// SelectUserAgent returns the value of list that (key, host) gets
// (SelectIndex); "" for an empty list.
func SelectUserAgent(key, host string, list []string) string {
	i := SelectIndex(key, host, len(list))
	if i < 0 {
		return ""
	}
	return list[i]
}
