package secretref

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// The fetch: POST /api/v2/sensor/commands/{command_id}/secrets.
//
// The request body is a FetchRequest, sent in a request the sensor signs
// with its key-bound identity (RFC 9421 with a Content-Digest), so the reply
// key and the lease epoch are covered by the signature. The answer is a
// SealedAnswer with content type ContentType and Cache-Control: no-store:
// an Answer, encoded as JSON, sealed with HPKE (RFC 9180, base mode,
// single shot, suite SuiteHybridV1) to the reply key, with Info as the HPKE
// info and no additional data. The platform answers every refusal with the
// protocol's command-not-found problem.

// Action is the last path segment of the fetch route.
const Action = "secrets"

// ContentType is the content type of a SealedAnswer.
const ContentType = "application/vnd.openctem.secrets+sealed"

// SuiteHybridV1 is the HPKE suite of a SealedAnswer: KEM ML-KEM-768+X25519,
// KDF HKDF-SHA256, AEAD ChaCha20-Poly1305 (the suite of the sealed-envelope
// format the platform and the sensor already share).
const SuiteHybridV1 = 1

// Bounds of the fetch.
const (
	// MaxReplyKeyLen bounds FetchRequest.ReplyKey (base64url text).
	MaxReplyKeyLen = 4096
	// MaxSealedLen bounds SealedAnswer.Sealed (base64url text).
	MaxSealedLen = 1 << 20
	// MaxAnswerSkew is how far an Answer's IssuedAt may be from the
	// sensor's clock.
	MaxAnswerSkew = 10 * time.Minute
)

// InfoLabel starts the HPKE info of a SealedAnswer.
const InfoLabel = "openctem-task-secrets/v1"

// FetchRequest is the signed body of a fetch.
type FetchRequest struct {
	// LeaseEpoch is the epoch of the lease the sensor holds on the command.
	// It is inside the signed body: a header the signature does not cover
	// never decides the lease.
	LeaseEpoch int64 `json:"lease_epoch"`
	// Task names the task the values are for (audit only).
	Task string `json:"task,omitempty"`
	// Refs are the ids of the job's refs the task needs: a subset of the
	// job's Set, at least one, no duplicates.
	Refs []string `json:"refs"`
	// ReplyKey is the base64url (no padding) of the single-use HPKE public
	// key the answer is sealed to. The sensor makes a new key pair for every
	// request and drops the private half once the answer is open.
	ReplyKey string `json:"reply_key"`
}

// Validate checks the request's shape. It does not check the refs against
// a job (the platform does).
func (f FetchRequest) Validate() error {
	if f.LeaseEpoch < 1 {
		return invalid("lease_epoch must be positive")
	}
	if len(f.Task) > MaxTaskLen || (f.Task != "" && !taskPattern.MatchString(f.Task)) {
		return invalid("invalid task")
	}
	if len(f.Refs) == 0 || len(f.Refs) > MaxRefs {
		return invalid("refs must name 1 to %d refs", MaxRefs)
	}
	seen := make(map[string]bool, len(f.Refs))
	for _, id := range f.Refs {
		if !ValidID(id) || seen[id] {
			return invalid("invalid or repeated ref id")
		}
		seen[id] = true
	}
	if f.ReplyKey == "" || len(f.ReplyKey) > MaxReplyKeyLen {
		return invalid("invalid reply_key")
	}
	if _, err := base64.RawURLEncoding.DecodeString(f.ReplyKey); err != nil {
		return invalid("reply_key must be base64url without padding")
	}
	return nil
}

// ReplyKeyBytes decodes ReplyKey.
func (f FetchRequest) ReplyKeyBytes() ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(f.ReplyKey)
	if err != nil {
		return nil, invalid("reply_key must be base64url without padding")
	}
	return b, nil
}

// KeyID is the hex of the first 16 bytes of the SHA-256 of a public key: the
// SealedAnswer's KeyID for the reply key.
func KeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// SealedAnswer is the body of a fetch's 200 answer.
type SealedAnswer struct {
	// Suite is SuiteHybridV1.
	Suite int `json:"suite"`
	// KeyID is KeyID of the reply key the answer is sealed to.
	KeyID string `json:"key_id"`
	// Sealed is the base64url (no padding) of the HPKE single-shot output
	// (encapsulated key followed by the ciphertext).
	Sealed string `json:"sealed"`
}

// Validate checks the answer's shape against the reply key it should be
// sealed to.
func (a SealedAnswer) Validate(replyKey []byte) error {
	if a.Suite != SuiteHybridV1 {
		return invalid("unsupported suite")
	}
	if a.KeyID != KeyID(replyKey) {
		return invalid("the answer is sealed to another key")
	}
	if a.Sealed == "" || len(a.Sealed) > MaxSealedLen {
		return invalid("invalid sealed answer")
	}
	return nil
}

// SealedBytes decodes Sealed.
func (a SealedAnswer) SealedBytes() ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(a.Sealed)
	if err != nil {
		return nil, invalid("sealed must be base64url without padding")
	}
	return b, nil
}

// Info is the HPKE info of the answer to one request:
//
//	InfoLabel 0x00 ||
//	u16 len || sensor id || u16 len || command id ||
//	u64 lease epoch || SHA-256 of the exact request body bytes
//
// (lengths and the epoch big-endian). An answer moved to another sensor,
// command, epoch or request does not open.
func Info(sensorID, commandID string, leaseEpoch int64, requestBody []byte) []byte {
	sum := sha256.Sum256(requestBody)
	out := make([]byte, 0, len(InfoLabel)+1+2+len(sensorID)+2+len(commandID)+8+len(sum))
	out = append(out, InfoLabel...)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(min(len(sensorID), 0xffff)))
	out = append(out, sensorID...)
	out = binary.BigEndian.AppendUint16(out, uint16(min(len(commandID), 0xffff)))
	out = append(out, commandID...)
	out = binary.BigEndian.AppendUint64(out, uint64(max(leaseEpoch, 0)))
	return append(out, sum[:]...)
}

// Provenances of a value.
const (
	// ProvenanceTenant: the organization's value stored on the platform.
	ProvenanceTenant = "platform:tenant"
)

// Answer is the plaintext of a SealedAnswer.
type Answer struct {
	CommandID  string    `json:"command_id"`
	LeaseEpoch int64     `json:"lease_epoch"`
	IssuedAt   time.Time `json:"issued_at"`
	Secrets    []Secret  `json:"secrets"`
	Missing    []Missing `json:"missing,omitempty"`
}

// Secret is one value.
type Secret struct {
	// ID is the ref's id.
	ID string `json:"id"`
	// Kind is the ref's kind.
	Kind string `json:"kind"`
	// Value is the kind's value shape (ProviderKey, EgressProxy).
	Value json.RawMessage `json:"value"`
	// Provenance is where the value comes from (Provenance* constants).
	Provenance string `json:"provenance"`
	// ExpiresAt is when the value stops working (nil: not known).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Missing is a ref the platform holds no value for.
type Missing struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Check is the sensor's check of an opened answer: it is for commandID at
// leaseEpoch, recent, and every value answers a ref the request asked for,
// once, with the ref's kind and a value the kind's validator accepts. The
// values are not repeated in an error.
func (a Answer) Check(set Set, commandID string, leaseEpoch int64, asked []string, now time.Time) error {
	if a.CommandID != commandID || a.LeaseEpoch != leaseEpoch {
		return invalid("the answer is for another command or lease")
	}
	if a.IssuedAt.IsZero() || a.IssuedAt.Sub(now) > MaxAnswerSkew || now.Sub(a.IssuedAt) > MaxAnswerSkew {
		return invalid("the answer is not recent")
	}
	seen := map[string]bool{}
	for _, s := range a.Secrets {
		if !slices.Contains(asked, s.ID) || seen[s.ID] {
			return invalid("the answer holds a value that was not asked for")
		}
		seen[s.ID] = true
		ref, ok := set.Lookup(s.ID)
		if !ok || ref.Kind != s.Kind {
			return invalid("the answer's value %s does not match the job's ref", s.ID)
		}
		if s.Provenance != ProvenanceTenant {
			return invalid("the answer's value %s has an unknown provenance", s.ID)
		}
		if err := ValidateValue(ref, s.Value); err != nil {
			return err
		}
	}
	for _, m := range a.Missing {
		if !slices.Contains(asked, m.ID) || seen[m.ID] || !KnownMissing(m.Reason) {
			return invalid("the answer's missing list is invalid")
		}
		seen[m.ID] = true
	}
	return nil
}
