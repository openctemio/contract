package secretref

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ProviderKey is the value of a KindProviderKey ref: the key written in its
// provider's format (Provider.ValidateKey).
type ProviderKey struct {
	Key string `json:"key"`
}

// EgressProxy is the value of a KindEgressProxy ref: the credentials of the
// pool's endpoints that have some.
type EgressProxy struct {
	Endpoints []ProxyEndpoint `json:"endpoints"`
}

// ProxyEndpoint is one pool endpoint's credentials.
type ProxyEndpoint struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Bounds of values.
const (
	// MaxProxyEndpoints bounds EgressProxy.Endpoints.
	MaxProxyEndpoints = 64
	// MaxProxyCredentialLen bounds a proxy user name or password.
	MaxProxyCredentialLen = 1024
)

// decodeStrict decodes raw into v, refusing unknown members and trailing
// data.
func decodeStrict(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("malformed value")
	}
	if dec.More() {
		return invalid("malformed value")
	}
	return nil
}

// ValidateValue checks the value of ref against its kind's rules (the same
// rules the platform applies when the value is saved). An unknown kind is
// refused.
func ValidateValue(ref Ref, raw json.RawMessage) error {
	switch ref.Kind {
	case KindProviderKey:
		_, err := DecodeProviderKey(ref, raw)
		return err
	case KindEgressProxy:
		_, err := DecodeEgressProxy(raw)
		return err
	}
	return invalid("unsupported kind")
}

// DecodeProviderKey decodes and validates the value of a provider key ref.
func DecodeProviderKey(ref Ref, raw json.RawMessage) (ProviderKey, error) {
	var v ProviderKey
	if err := decodeStrict(raw, &v); err != nil {
		return ProviderKey{}, err
	}
	p, ok := LookupProvider(ref.Ref)
	if !ok {
		return ProviderKey{}, invalid("unknown provider")
	}
	if err := p.ValidateKey(v.Key); err != nil {
		return ProviderKey{}, err
	}
	return v, nil
}

// DecodeEgressProxy decodes and validates the value of an egress proxy ref.
func DecodeEgressProxy(raw json.RawMessage) (EgressProxy, error) {
	var v EgressProxy
	if err := decodeStrict(raw, &v); err != nil {
		return EgressProxy{}, err
	}
	if len(v.Endpoints) > MaxProxyEndpoints {
		return EgressProxy{}, invalid("too many proxy endpoints")
	}
	seen := map[string]bool{}
	for _, e := range v.Endpoints {
		if e.ID == "" || len(e.ID) > MaxRefLen || !refPattern.MatchString(e.ID) || seen[e.ID] {
			return EgressProxy{}, invalid("invalid proxy endpoint id")
		}
		seen[e.ID] = true
		if len(e.Username) > MaxProxyCredentialLen || len(e.Password) > MaxProxyCredentialLen ||
			strings.ContainsAny(e.Username, "\x00\r\n") || strings.ContainsAny(e.Password, "\x00\r\n") {
			return EgressProxy{}, invalid("invalid proxy credentials")
		}
	}
	return v, nil
}
