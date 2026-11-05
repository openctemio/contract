package secretref

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// The provider registry: every third-party source a tool queries with a key
// the platform may store and deliver. One table drives the platform's
// catalog and save validation, the sensor's check of a delivered or local
// key, and the hosts the sensor lets the task reach with that key.

// Key formats.
const (
	// FormatKey is a single key or token.
	FormatKey = "key"
	// FormatPair is two parts joined by one colon (PairHint names them).
	FormatPair = "pair"
)

// Endpoint kinds of a key whose first part names where the tool sends it.
const (
	// EndpointHost: "HOST:KEY", HOST a DNS name HostRule accepts.
	EndpointHost = "host"
	// EndpointURL: "https://HOST/PATH:KEY", HOST a DNS name HostRule
	// accepts; no port, user information, query or fragment.
	EndpointURL = "url"
)

// Key bounds.
const (
	// MaxKeyLen bounds a key.
	MaxKeyLen = 1024
	// MinSecretLen is the shortest secret part of a key: shorter values are
	// not real keys, and a sensor scrubs only values of at least this
	// length from a task's output reliably.
	MinSecretLen = 8
)

// Key error codes (KeyError.Code).
const (
	KeyEmpty    = "empty"
	KeyTooLong  = "too_long"
	KeyInvalid  = "invalid"
	KeyFormat   = "format"
	KeyEndpoint = "endpoint"
	KeyTooShort = "too_short"
)

// KeyError is a key that a provider's rules refuse. It never holds the key.
type KeyError struct {
	Code string
	Msg  string
}

func (e *KeyError) Error() string { return "secretref: invalid: " + e.Msg }

// Unwrap makes a KeyError match ErrInvalid.
func (e *KeyError) Unwrap() error { return ErrInvalid }

// Provider is one entry of the registry.
type Provider struct {
	// ID is the provider id: the Ref of a provider key ref, and the tool's
	// credential slot name.
	ID string `json:"id"`
	// Display is the provider's name for people.
	Display string `json:"display"`
	// Format is FormatKey or FormatPair.
	Format string `json:"format"`
	// PairHint names the two parts of a pair ("TOKEN:ORG_ID").
	PairHint string `json:"pair_hint,omitempty"`
	// Hosts are the hosts a tool sends the key to.
	Hosts []string `json:"hosts"`
	// Endpoint is EndpointHost or EndpointURL when the key's first part
	// names the host the tool connects to; "" otherwise.
	Endpoint string `json:"endpoint,omitempty"`
	// HostRule is the anchored pattern that host must match.
	HostRule string `json:"host_rule,omitempty"`
	// HostPrefix is put before the key's host to give the host the tool
	// connects to ("api." for a key naming "zoomeye.ai").
	HostPrefix string `json:"host_prefix,omitempty"`
	// Tools are the tools that query the provider with the key.
	Tools []string `json:"tools"`

	rule *regexp.Regexp
}

//go:embed providers.json
var providersJSON []byte

type registryFile struct {
	Version   int        `json:"version"`
	Providers []Provider `json:"providers"`
}

var registry = mustLoad(providersJSON)

var (
	hostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	urlPath     = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
)

func mustLoad(b []byte) []Provider {
	ps, err := loadRegistry(b)
	if err != nil {
		panic(err)
	}
	return ps
}

// loadRegistry parses and checks a registry: ids unique and valid, a known
// format, hosts that are lower-case DNS names, and a host rule (anchored)
// exactly for a provider whose key names its endpoint.
func loadRegistry(b []byte) ([]Provider, error) {
	var f registryFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("secretref: providers: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("secretref: providers: version %d", f.Version)
	}
	seen := map[string]bool{}
	for i := range f.Providers {
		p := &f.Providers[i]
		if !slotPattern.MatchString(p.ID) || seen[p.ID] {
			return nil, fmt.Errorf("secretref: providers: invalid or repeated id %q", p.ID)
		}
		seen[p.ID] = true
		if p.Format != FormatKey && p.Format != FormatPair {
			return nil, fmt.Errorf("secretref: providers: %s: format %q", p.ID, p.Format)
		}
		if (p.Format == FormatPair) != (p.PairHint != "") {
			return nil, fmt.Errorf("secretref: providers: %s: a pair has a hint, a key none", p.ID)
		}
		for _, h := range p.Hosts {
			if !hostPattern.MatchString(h) {
				return nil, fmt.Errorf("secretref: providers: %s: host %q", p.ID, h)
			}
		}
		switch p.Endpoint {
		case "":
			if p.HostRule != "" || p.HostPrefix != "" || len(p.Hosts) == 0 {
				return nil, fmt.Errorf("secretref: providers: %s: fixed hosts, no rule", p.ID)
			}
		case EndpointHost, EndpointURL:
			if p.Format != FormatPair || !strings.HasPrefix(p.HostRule, "^") || !strings.HasSuffix(p.HostRule, "$") {
				return nil, fmt.Errorf("secretref: providers: %s: an endpoint key is a pair with an anchored rule", p.ID)
			}
			rule, err := regexp.Compile(p.HostRule)
			if err != nil {
				return nil, fmt.Errorf("secretref: providers: %s: %w", p.ID, err)
			}
			p.rule = rule
			if p.HostPrefix != "" && !hostPattern.MatchString(p.HostPrefix+"example.com") {
				return nil, fmt.Errorf("secretref: providers: %s: host prefix", p.ID)
			}
		default:
			return nil, fmt.Errorf("secretref: providers: %s: endpoint %q", p.ID, p.Endpoint)
		}
		if len(p.Tools) == 0 {
			return nil, fmt.Errorf("secretref: providers: %s: no tool", p.ID)
		}
	}
	sort.Slice(f.Providers, func(i, j int) bool { return f.Providers[i].ID < f.Providers[j].ID })
	return f.Providers, nil
}

func (p Provider) clone() Provider {
	p.Hosts = slices.Clone(p.Hosts)
	p.Tools = slices.Clone(p.Tools)
	return p
}

// Providers returns every provider, ordered by id.
func Providers() []Provider {
	out := make([]Provider, len(registry))
	for i, p := range registry {
		out[i] = p.clone()
	}
	return out
}

// LookupProvider returns the provider id names.
func LookupProvider(id string) (Provider, bool) {
	i := slices.IndexFunc(registry, func(p Provider) bool { return p.ID == id })
	if i < 0 {
		return Provider{}, false
	}
	return registry[i].clone(), true
}

// ProvidersForTool returns the ids of the providers tool queries with a key.
func ProvidersForTool(tool string) []string {
	var out []string
	for _, p := range registry {
		if slices.Contains(p.Tools, tool) {
			out = append(out, p.ID)
		}
	}
	return out
}

func keyErr(code, msg string) error { return &KeyError{Code: code, Msg: msg} }

// ValidateKey checks a key: 1 to MaxKeyLen visible ASCII characters (no
// spaces or line breaks: a key reaches a tool's configuration file, never a
// command line), a secret part of at least MinSecretLen characters, for a
// pair exactly one colon between two non-empty parts, and for a key whose
// first part names where the tool connects, a host on the provider's own
// service only (never an IP address, port, user information or other
// host). Errors never repeat the key.
func (p Provider) ValidateKey(v string) error {
	if v == "" {
		return keyErr(KeyEmpty, "the key is empty")
	}
	if len(v) > MaxKeyLen {
		return keyErr(KeyTooLong, fmt.Sprintf("the key is longer than %d characters", MaxKeyLen))
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return keyErr(KeyInvalid, "the key may contain only visible ASCII characters, without spaces")
		}
	}
	if _, err := p.endpointHost(v); err != nil {
		return err
	}
	if len(p.SecretPart(v)) < MinSecretLen {
		return keyErr(KeyTooShort, fmt.Sprintf("the key is shorter than %d characters", MinSecretLen))
	}
	return nil
}

// endpointHost checks the format of v and returns the host its first part
// names ("" for a key that names none).
func (p Provider) endpointHost(v string) (string, error) {
	formatErr := keyErr(KeyFormat, "the key must be written as "+p.PairHint)
	switch {
	case p.Format != FormatPair:
		return "", nil
	case p.Endpoint == EndpointURL:
		// "https://HOST/PATH:KEY": exactly the scheme's colon and the
		// separator (a tool may split the value on every colon).
		parts := strings.Split(v, ":")
		if len(parts) != 3 || parts[0] != "https" || parts[2] == "" {
			return "", formatErr
		}
		host, ok := p.endpointURLHost("https:" + parts[1])
		if !ok {
			return "", keyErr(KeyEndpoint, "the endpoint must be an https URL on the "+p.Display+" service")
		}
		return host, nil
	default:
		a, b, ok := strings.Cut(v, ":")
		if !ok || a == "" || b == "" || strings.Contains(b, ":") {
			return "", formatErr
		}
		if p.Endpoint == EndpointHost {
			if !p.hostAllowed(a) {
				return "", keyErr(KeyEndpoint, "the host must be a "+p.Display+" host name")
			}
			return a, nil
		}
		return "", nil
	}
}

// hostAllowed reports whether host is a DNS name the provider's rule
// accepts.
func (p Provider) hostAllowed(host string) bool {
	return p.rule != nil && hostPattern.MatchString(host) && p.rule.MatchString(host)
}

func (p Provider) endpointURLHost(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		u.ForceQuery {
		return "", false
	}
	if u.Port() != "" || u.Host != u.Hostname() || !p.hostAllowed(u.Hostname()) {
		return "", false
	}
	if !urlPath.MatchString(u.EscapedPath()) {
		return "", false
	}
	return u.Hostname(), true
}

// Audience returns the hosts a tool may send key v to: the provider's fixed
// hosts and, for a key that names its endpoint, that host (with
// HostPrefix). v must pass ValidateKey.
func (p Provider) Audience(v string) ([]string, error) {
	if err := p.ValidateKey(v); err != nil {
		return nil, err
	}
	out := slices.Clone(p.Hosts)
	h, err := p.endpointHost(v)
	if err != nil {
		return nil, err
	}
	if h != "" {
		h = p.HostPrefix + h
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out, nil
}

// SecretPart is the part of a key that is the secret: the whole key, or the
// last part of a pair.
func (p Provider) SecretPart(v string) string {
	if p.Format != FormatPair {
		return v
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

// Last4 is the part of a key shown after it is saved: the last four
// characters of its secret part (never a user name or app id), nothing when
// that part is shorter than 12 characters.
func (p Provider) Last4(v string) string {
	sec := p.SecretPart(v)
	if len(sec) < 12 {
		return ""
	}
	return sec[len(sec)-4:]
}
