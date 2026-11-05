package secretref

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func providerRef(id, provider string) Ref {
	return Ref{ID: id, Kind: KindProviderKey, Class: ClassProvider, Ref: provider, Slot: provider, Audience: []string{AudienceProvider(provider)},
		Consumer: ConsumerTool, Local: LocalAllow}
}

func poolRef(id string) Ref {
	return Ref{ID: id, Kind: KindEgressProxy, Class: ClassProvider, Ref: "0193a3f2-7c1e-7b4c-9d1a-2f6e8c4b5a10", Audience: []string{AudiencePool},
		Consumer: ConsumerForwarder, Local: LocalNever, Required: true}
}

func goodSet() Set {
	return Set{V: Version, Local: LocalAllow, Refs: []Ref{providerRef("k1", "shodan"), providerRef("k2", "censys"), poolRef("p1")}}
}

func TestSetValidate(t *testing.T) {
	if err := goodSet().Validate(); err != nil {
		t.Fatal(err)
	}
	unknown := goodSet()
	unknown.Refs = append(unknown.Refs, Ref{ID: "x1", Kind: "http_auth", Class: ClassTarget, Ref: "c1", Slot: "auth", Audience: []string{AudienceTargets}, Consumer: ConsumerTool, Local: LocalOnly, Required: true})
	if err := unknown.Validate(); err != nil {
		t.Fatalf("an unknown kind passes the generic rules: %v", err)
	}
	if KnownKind("client_cert") || !KnownKind(KindProviderKey) || !KnownKind(KindEgressProxy) {
		t.Fatal("KnownKind")
	}
}

func TestSetRefuses(t *testing.T) {
	cases := map[string]func(*Set){
		"version":          func(s *Set) { s.V = 2 },
		"set local only":   func(s *Set) { s.Local = LocalOnly },
		"set local empty":  func(s *Set) { s.Local = "" },
		"duplicate id":     func(s *Set) { s.Refs[1].ID = "k1" },
		"duplicate slot":   func(s *Set) { s.Refs[1].Slot = "shodan" },
		"long id":          func(s *Set) { s.Refs[0].ID = "abcdefghi" },
		"upper id":         func(s *Set) { s.Refs[0].ID = "K1" },
		"unknown provider": func(s *Set) { s.Refs[0].Ref = "nope"; s.Refs[0].Audience = []string{"provider:nope"} },
		"foreign audience": func(s *Set) { s.Refs[0].Audience = []string{"provider:censys"} },
		"two audiences":    func(s *Set) { s.Refs[0].Audience = append(s.Refs[0].Audience, "targets") },
		"key to forwarder": func(s *Set) { s.Refs[0].Consumer = ConsumerForwarder },
		"key without slot": func(s *Set) { s.Refs[0].Slot = "" },
		"bad local":        func(s *Set) { s.Refs[0].Local = "sometimes" },
		"pool to tool":     func(s *Set) { s.Refs[2].Consumer = ConsumerTool },
		"pool with slot":   func(s *Set) { s.Refs[2].Slot = "proxy" },
		"pool local":       func(s *Set) { s.Refs[2].Local = LocalAllow },
		"pool audience":    func(s *Set) { s.Refs[2].Audience = []string{"provider:shodan"} },
		"ref with space":   func(s *Set) { s.Refs[2].Ref = "a b" },
		"unknown consumer": func(s *Set) {
			s.Refs = append(s.Refs, Ref{ID: "x", Kind: "other", Class: ClassProvider, Ref: "r", Consumer: "env", Local: LocalNever})
		},
		"too many refs":  func(s *Set) { s.Refs = make([]Ref, MaxRefs+1) },
		"no class":       func(s *Set) { s.Refs[0].Class = "" },
		"key as target":  func(s *Set) { s.Refs[0].Class = ClassTarget },
		"pool as target": func(s *Set) { s.Refs[2].Class = ClassTarget },
		"target to provider host": func(s *Set) {
			s.Refs = append(s.Refs, Ref{ID: "t1", Kind: "http_auth", Class: ClassTarget, Ref: "c1", Slot: "auth", Audience: []string{"provider:shodan"}, Consumer: ConsumerTool, Local: LocalNever})
		},
		"target to forwarder": func(s *Set) {
			s.Refs = append(s.Refs, Ref{ID: "t1", Kind: "http_auth", Class: ClassTarget, Ref: "c1", Audience: []string{AudienceTargets}, Consumer: ConsumerForwarder, Local: LocalNever})
		},
		"audience with tabs": func(s *Set) { s.Refs[0].Audience = []string{"provider:shodan\t"} },
	}
	for name, mut := range cases {
		s := goodSet()
		mut(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSetLookup(t *testing.T) {
	s := goodSet()
	if r, ok := s.Lookup("k2"); !ok || r.Ref != "censys" {
		t.Fatal("Lookup")
	}
	if _, ok := s.Lookup("zz"); ok {
		t.Fatal("Lookup unknown")
	}
	if r, ok := s.ForSlot("shodan"); !ok || r.ID != "k1" {
		t.Fatal("ForSlot")
	}
	if _, ok := s.ForSlot(""); ok {
		t.Fatal("the pool fills no slot")
	}
}

func replyKey() string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 1216)) }

func TestFetchRequestValidate(t *testing.T) {
	good := FetchRequest{LeaseEpoch: 3, Task: "chunk-2", Refs: []string{"k1", "p1"}, ReplyKey: replyKey()}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*FetchRequest){
		"zero epoch":      func(f *FetchRequest) { f.LeaseEpoch = 0 },
		"no refs":         func(f *FetchRequest) { f.Refs = nil },
		"repeated ref":    func(f *FetchRequest) { f.Refs = []string{"k1", "k1"} },
		"bad ref":         func(f *FetchRequest) { f.Refs = []string{"K1"} },
		"long task":       func(f *FetchRequest) { f.Task = strings.Repeat("a", MaxTaskLen+1) },
		"task newline":    func(f *FetchRequest) { f.Task = "a\nb" },
		"no reply key":    func(f *FetchRequest) { f.ReplyKey = "" },
		"padded key":      func(f *FetchRequest) { f.ReplyKey = base64.URLEncoding.EncodeToString([]byte{1, 2}) },
		"std alphabet":    func(f *FetchRequest) { f.ReplyKey = "+/+/" },
		"huge reply key":  func(f *FetchRequest) { f.ReplyKey = strings.Repeat("A", MaxReplyKeyLen+1) },
		"too many refs":   func(f *FetchRequest) { f.Refs = make([]string, MaxRefs+1) },
		"negative epoch":  func(f *FetchRequest) { f.LeaseEpoch = -1 },
		"task with space": func(f *FetchRequest) { f.Task = "a b" },
	}
	for name, mut := range cases {
		f := good
		f.Refs = append([]string(nil), good.Refs...)
		mut(&f)
		if err := f.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestInfoVector pins the HPKE info bytes: the platform and the sensor build
// them with this function, and a change here breaks every sensor.
func TestInfoVector(t *testing.T) {
	got := Info("0193a3f2-0000-7000-8000-000000000001", "0193a3f2-0000-7000-8000-000000000002", 3, []byte(`{"lease_epoch":3}`))
	if !bytes.HasPrefix(got, []byte(InfoLabel+"\x00\x00\x24")) || len(got) != len(InfoLabel)+1+2+36+2+36+8+32 {
		t.Fatalf("info layout %x", got)
	}
	vec, err := readInfoVector()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vec {
		t.Fatalf("info %x\nwant %s", got, vec)
	}
	// Every field changes the info.
	base := hex.EncodeToString(got)
	for name, other := range map[string][]byte{
		"sensor":  Info("0193a3f2-0000-7000-8000-000000000009", "0193a3f2-0000-7000-8000-000000000002", 3, []byte(`{"lease_epoch":3}`)),
		"command": Info("0193a3f2-0000-7000-8000-000000000001", "0193a3f2-0000-7000-8000-000000000009", 3, []byte(`{"lease_epoch":3}`)),
		"epoch":   Info("0193a3f2-0000-7000-8000-000000000001", "0193a3f2-0000-7000-8000-000000000002", 4, []byte(`{"lease_epoch":3}`)),
		"body":    Info("0193a3f2-0000-7000-8000-000000000001", "0193a3f2-0000-7000-8000-000000000002", 3, []byte(`{"lease_epoch":4}`)),
		"split":   Info("0193a3f2-0000-7000-8000-000000000001\x00\x24", "0193a3f2-0000-7000-8000-00000000000", 3, []byte(`{"lease_epoch":3}`)),
	} {
		if hex.EncodeToString(other) == base {
			t.Errorf("%s does not change the info", name)
		}
	}
}

func readTestdata(name string) ([]byte, error) { return os.ReadFile("testdata/" + name) }

func readInfoVector() (string, error) {
	var v struct {
		Info string `json:"info_hex"`
	}
	b, err := readTestdata("info-vector.json")
	if err != nil {
		return "", err
	}
	return v.Info, json.Unmarshal(b, &v)
}

func TestSealedAnswerValidate(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 1216)
	a := SealedAnswer{Suite: SuiteHybridV1, KeyID: KeyID(key), Sealed: "AAAA"}
	if err := a.Validate(key); err != nil {
		t.Fatal(err)
	}
	if len(a.KeyID) != 32 {
		t.Fatalf("key id %q", a.KeyID)
	}
	for name, b := range map[string]SealedAnswer{
		"suite":     {Suite: 2, KeyID: a.KeyID, Sealed: "AAAA"},
		"other key": {Suite: 1, KeyID: KeyID([]byte{1}), Sealed: "AAAA"},
		"empty":     {Suite: 1, KeyID: a.KeyID},
	} {
		if err := b.Validate(key); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (SealedAnswer{Sealed: "AA=="}).SealedBytes(); err == nil {
		t.Fatal("padded sealed accepted")
	}
}

func value(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnswerCheck(t *testing.T) {
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	set := goodSet()
	asked := []string{"k1", "k2", "p1"}
	good := func() Answer {
		return Answer{CommandID: "c1", LeaseEpoch: 3, IssuedAt: now, Secrets: []Secret{
			{ID: "k1", Kind: KindProviderKey, Value: value(t, ProviderKey{Key: "abcdefgh12345678"}), Provenance: ProvenanceTenant},
			{ID: "p1", Kind: KindEgressProxy, Value: value(t, EgressProxy{Endpoints: []ProxyEndpoint{{ID: "e1", Username: "u", Password: "p"}}}), Provenance: ProvenanceTenant},
		}, Missing: []Missing{{ID: "k2", Reason: MissingDisabled}}}
	}
	a := good()
	if err := a.Check(set, "c1", 3, asked, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Answer){
		"other command": func(a *Answer) { a.CommandID = "c2" },
		"other epoch":   func(a *Answer) { a.LeaseEpoch = 2 },
		"old":           func(a *Answer) { a.IssuedAt = now.Add(-time.Hour) },
		"future":        func(a *Answer) { a.IssuedAt = now.Add(time.Hour) },
		"zero time":     func(a *Answer) { a.IssuedAt = time.Time{} },
		"not asked":     func(a *Answer) { a.Secrets[0].ID = "zz" },
		"twice":         func(a *Answer) { a.Secrets[1] = a.Secrets[0] },
		"kind swap":     func(a *Answer) { a.Secrets[0].Kind = KindEgressProxy },
		"provenance":    func(a *Answer) { a.Secrets[0].Provenance = "local" },
		"bad key":       func(a *Answer) { a.Secrets[0].Value = value(t, ProviderKey{Key: "short"}) },
		"extra member":  func(a *Answer) { a.Secrets[0].Value = json.RawMessage(`{"key":"abcdefgh12345678","x":1}`) },
		"trailing data": func(a *Answer) { a.Secrets[0].Value = json.RawMessage(`{"key":"abcdefgh12345678"} {}`) },
		"proxy newline": func(a *Answer) {
			a.Secrets[1].Value = value(t, EgressProxy{Endpoints: []ProxyEndpoint{{ID: "e1", Password: "a\r\nb"}}})
		},
		"missing reason":    func(a *Answer) { a.Missing[0].Reason = "because" },
		"missing and value": func(a *Answer) { a.Missing[0].ID = "k1" },
		"missing not asked": func(a *Answer) { a.Missing[0].ID = "zz" },
	}
	for name, mut := range cases {
		a := good()
		mut(&a)
		err := a.Check(set, "c1", 3, asked, now)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "abcdefgh12345678") {
			t.Errorf("%s: the error repeats the value", name)
		}
	}
	// The ref's own provider decides: an intelx key naming a foreign host
	// is refused even when the answer is otherwise well formed.
	ix := Set{V: Version, Local: LocalNever, Refs: []Ref{providerRef("k1", "intelx")}}
	a = good()
	a.Secrets, a.Missing = a.Secrets[:1], nil
	a.Secrets[0].Value = value(t, ProviderKey{Key: "evil.example:abcdefgh1234"})
	if err := a.Check(ix, "c1", 3, []string{"k1"}, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("an intelx key with a foreign host accepted")
	}
}

func TestValidateValueUnknownKind(t *testing.T) {
	if err := ValidateValue(Ref{Kind: "client_cert"}, json.RawMessage(`{}`)); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := DecodeEgressProxy(value(t, EgressProxy{Endpoints: []ProxyEndpoint{{ID: "e1"}, {ID: "e1"}}})); err == nil {
		t.Fatal("repeated endpoint accepted")
	}
	if _, err := DecodeEgressProxy(value(t, EgressProxy{Endpoints: make([]ProxyEndpoint, MaxProxyEndpoints+1)})); err == nil {
		t.Fatal("too many endpoints accepted")
	}
}

func TestConsumerOf(t *testing.T) {
	if ClassOf(KindProviderKey) != ClassProvider || ClassOf(KindEgressProxy) != ClassProvider || ClassOf("http_auth") != "" || !KnownClass(ClassTarget) {
		t.Fatal("ClassOf")
	}
	if ConsumerOf(KindProviderKey) != ConsumerTool || ConsumerOf(KindEgressProxy) != ConsumerForwarder || ConsumerOf("x") != "" {
		t.Fatal("ConsumerOf")
	}
}
