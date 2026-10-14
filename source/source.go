// Package source is the one definition of where the code of a platform code
// scan comes from: a repository, a branch and the exact commit to scan. The
// platform puts a Repository in the job it hands a sensor; the sensor
// fetches exactly that commit, read-only, and refuses anything this package
// refuses. Both sides validate with the same code, so a sensor never fetches
// what the platform would not have sent.
//
// A Repository carries no secret. Credential names the credential the
// sensor asks the platform for when it starts the job (a short-lived,
// read-only token for this one repository); the token itself never travels
// in the job and is never stored with it.
package source

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/openctemio/ctis/capability"
)

// Repository is the source of a code scan.
type Repository struct {
	// Kind is the SCM the repository lives in (Kind* constants). It tells
	// the platform how to mint the credential; the fetch is plain git over
	// HTTPS for every kind.
	Kind string `json:"kind"`
	// CloneURL is the HTTPS URL of the repository: no user information,
	// query or fragment, a host name (not an address), an optional port.
	CloneURL string `json:"clone_url"`
	// Branch is the branch the commit belongs to (a protected branch).
	Branch string `json:"branch"`
	// Commit is the full commit id (40 or 64 lower-case hex characters) to
	// scan. The fetch fails when the branch head is another commit only if
	// the commit itself cannot be fetched; the scan is always of Commit.
	Commit string `json:"commit"`
	// Depth is the history to fetch: 1 (the default, 0 means 1) or up to
	// MaxDepth commits for scans that read history (secrets in history).
	Depth int `json:"depth,omitempty"`
	// Credential names the credential the sensor asks the platform for
	// ("" for a public repository fetched anonymously). A name, never a
	// value.
	Credential string `json:"credential,omitempty"`
	// Capabilities are the capability references to run on the checkout
	// ("sast.code@1", "secrets.code@1", "sca.deps@1", "iac.misconfig@1"):
	// each must take a repository as input.
	Capabilities []string `json:"capabilities"`
}

// SCM kinds.
const (
	KindGitHub    = "github"
	KindGitLab    = "gitlab"
	KindBitbucket = "bitbucket"
	KindAzure     = "azure"
	// KindGit is any other HTTPS git server (a public repository, or one
	// the sensor's operator configured a credential for).
	KindGit = "git"
)

// Limits.
const (
	MaxURLLength    = 2048
	MaxBranchLength = 255
	// MaxDepth bounds a history fetch.
	MaxDepth          = 10000
	maxCapabilities   = 16
	maxCredentialName = 64
)

// ErrInvalid wraps every validation error.
var ErrInvalid = errors.New("source: invalid repository")

var (
	commitRe     = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	credentialRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
	pathSegRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.~-]*$`)
)

// Normalize trims the fields, lower-cases the kind, the host and the commit,
// and defaults Depth to 1. Validate calls it.
func (r *Repository) Normalize() {
	r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
	r.CloneURL = strings.TrimSpace(r.CloneURL)
	if u, err := url.Parse(r.CloneURL); err == nil && u.Host != "" {
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		r.CloneURL = u.String()
	}
	r.Branch = strings.TrimSpace(r.Branch)
	r.Commit = strings.ToLower(strings.TrimSpace(r.Commit))
	r.Credential = strings.TrimSpace(r.Credential)
	if r.Depth == 0 {
		r.Depth = 1
	}
	caps := make([]string, 0, len(r.Capabilities))
	for _, c := range r.Capabilities {
		if c = strings.TrimSpace(c); c != "" && !slices.Contains(caps, c) {
			caps = append(caps, c)
		}
	}
	r.Capabilities = caps
}

// Validate normalizes r and checks every field. The error wraps ErrInvalid
// and names the field; it never echoes a URL's user information.
func (r *Repository) Validate() error {
	r.Normalize()
	switch r.Kind {
	case KindGitHub, KindGitLab, KindBitbucket, KindAzure, KindGit:
	default:
		return invalid("kind", "unknown SCM kind")
	}
	if err := CheckCloneURL(r.CloneURL); err != nil {
		return err
	}
	if !ValidBranch(r.Branch) {
		return invalid("branch", "not a branch name git accepts as a ref")
	}
	if !commitRe.MatchString(r.Commit) {
		return invalid("commit", "must be a full commit id (40 or 64 hex characters)")
	}
	if r.Depth < 1 || r.Depth > MaxDepth {
		return invalid("depth", fmt.Sprintf("must be 1 to %d", MaxDepth))
	}
	if r.Credential != "" && (len(r.Credential) > maxCredentialName || !credentialRe.MatchString(r.Credential)) {
		return invalid("credential", "must be a credential name (lower case letters, digits, '_', '.', '-')")
	}
	if len(r.Capabilities) == 0 || len(r.Capabilities) > maxCapabilities {
		return invalid("capabilities", fmt.Sprintf("must name 1 to %d capabilities", maxCapabilities))
	}
	for _, ref := range r.Capabilities {
		c, ok := capability.Lookup(ref)
		if !ok || !slices.Contains(c.InPorts, capability.PortType("repository")) {
			return invalid("capabilities", fmt.Sprintf("%q is not a capability that scans a repository", ref))
		}
	}
	return nil
}

// Host returns the host (and port) of CloneURL, "" when it cannot be read.
func (r Repository) Host() string {
	u, err := url.Parse(r.CloneURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// CheckCloneURL refuses anything but a plain HTTPS repository URL: scheme
// https, a DNS host name (an IP address is refused; the platform names the
// SCM host it holds a credential for), an optional port, no user
// information, query or fragment, and a path of ordinary segments (no "..",
// no segment starting with '-' or '.', which git or a server could read as
// an option or a hidden path).
func CheckCloneURL(raw string) error {
	if raw == "" || len(raw) > MaxURLLength {
		return invalid("clone_url", "is required and at most 2048 characters")
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '\\' }) {
		return invalid("clone_url", "contains a control character, a space or a backslash")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return invalid("clone_url", "is not a URL")
	}
	if u.Scheme != "https" {
		return invalid("clone_url", "must use https")
	}
	if u.User != nil {
		return invalid("clone_url", "must not carry user information (credentials are never part of the URL)")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return invalid("clone_url", "must not have a query or a fragment")
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil || strings.HasSuffix(host, ".") || !validHostname(host) {
		return invalid("clone_url", "must name a DNS host (not an address)")
	}
	if p := u.Port(); p != "" && (len(p) > 5 || strings.TrimLeft(p, "0123456789") != "" || p[0] == '0') {
		return invalid("clone_url", "has an invalid port")
	}
	path := strings.Trim(u.EscapedPath(), "/")
	if path == "" || u.RawPath != "" && u.RawPath != u.Path {
		return invalid("clone_url", "must name a repository path without escapes")
	}
	segs := strings.Split(path, "/")
	if len(segs) < 2 {
		return invalid("clone_url", "must name an owner and a repository")
	}
	for _, s := range segs {
		if !pathSegRe.MatchString(s) || s == ".." || strings.HasPrefix(s, "-") {
			return invalid("clone_url", "has a path segment that is not a plain name")
		}
	}
	return nil
}

func validHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return strings.Contains(h, ".")
}

// ValidBranch reports whether b is a branch name that is safe to pass to git
// as a ref: the rules of git check-ref-format for a branch, plus no leading
// '-' (an option) and at most MaxBranchLength bytes.
func ValidBranch(b string) bool {
	if b == "" || len(b) > MaxBranchLength || strings.HasPrefix(b, "-") || strings.HasPrefix(b, "/") ||
		strings.HasSuffix(b, "/") || strings.HasSuffix(b, ".") || strings.HasSuffix(b, ".lock") ||
		strings.Contains(b, "..") || strings.Contains(b, "//") || strings.Contains(b, "@{") || b == "@" {
		return false
	}
	for _, part := range strings.Split(b, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return !strings.ContainsFunc(b, func(r rune) bool {
		return r <= ' ' || r == 0x7f || strings.ContainsRune(`~^:?*[\`, r)
	})
}

func invalid(field, why string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalid, field, why)
}
