// Package secretref is the one definition of how a secret reaches a tool a
// sensor runs for the platform: the references a signed job carries, the
// per-task fetch that turns them into values, and the rules every value must
// meet. The platform and the sensor SDK both validate with this code, so a
// sensor never accepts what the platform would not have sent.
//
// The model:
//
//   - When a sensor claims a job, the platform lists in the job's payload
//     (member "secrets", a Set) the secrets the job may use: an id, a kind, the
//     stored row it names, the tool slot it fills, where its value may be sent
//     (its audience) and whether the sensor's own local value may stand in
//     (Local). The list is part of the payload before the job is signed, so
//     the job signature covers it. A Set carries names, never values.
//   - For each task, the sensor asks for the values of the refs that task
//     needs (FetchRequest), in an RFC 9421-signed request that also carries
//     the lease epoch and a single-use HPKE public key. The platform answers
//     only the live lease holder, only refs of that job, sealed to that key
//     (SealedAnswer); the HPKE info binds the answer to the sensor, the
//     command, the epoch and the exact request (Info). A TLS terminator, a
//     request log or a replayed request never holds a value.
//   - Every kind declares its consumer (the tool, or the sensor's egress
//     forwarder) and its audience. A provider key may be sent only to the
//     hosts of its provider in the registry (Providers), so the sensor narrows
//     the task's network scope to them.
//
// This package defines the shapes and the validators; the transport, the
// sealing and the storage live in the platform and the SDK.
package secretref

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Version is the version of a Set (Set.V) and of an Answer.
const Version = 1

// PayloadField is the job payload member that carries the Set.
const PayloadField = "secrets"

// Kinds of secret. A sensor that meets a kind it does not know on a required
// ref refuses the job (RefusalKindUnsupported); an unknown kind on an
// optional ref is skipped.
const (
	// KindProviderKey is a key of a third-party data source a tool queries
	// (a passive source of subfinder, for one). Ref is the provider id in
	// the registry; the value is a ProviderKey.
	KindProviderKey = "provider_key"
	// KindEgressProxy is the credentials of the job's proxy pool. Ref is the
	// pool id of the job's egress block; the value is an EgressProxy. The
	// sensor's egress forwarder consumes it; it never reaches a tool.
	KindEgressProxy = "egress_proxy"
)

// KnownKind reports whether kind is a kind of this version.
func KnownKind(kind string) bool {
	return kind == KindProviderKey || kind == KindEgressProxy
}

// Classes of secret: what a value opens. The class, not the vendor or the
// tool, decides the gates the platform applies when it lists a ref at claim
// and when it answers a fetch, and what the sensor lets the task reach.
const (
	// ClassProvider: access to a third-party data service a tool consults
	// (a passive DNS or search API), or the infrastructure the sensor's
	// traffic goes through (the job's proxy pool). Chosen automatically by
	// the tool's provider slots; its audience is the provider registry's
	// hosts (or the pool).
	ClassProvider = "provider"
	// ClassTarget: the organization's credentials to its own systems (a web
	// login, an API token of the target). Chosen by a person per scan, step
	// or asset, never automatically; it needs the sensor's grant to use
	// credentials, is refused on a shared sensor unless the organization
	// allows that sensor, and its audience is the task's own targets
	// (AudienceTargets) intersected with the credential's asset binding.
	ClassTarget = "target"
)

// KnownClass reports whether class is a class of this version.
func KnownClass(class string) bool { return class == ClassProvider || class == ClassTarget }

// ClassOf is the class of a known kind ("" for an unknown kind).
func ClassOf(kind string) string {
	switch kind {
	case KindProviderKey, KindEgressProxy:
		return ClassProvider
	}
	return ""
}

// Consumers: who on the sensor receives a value.
const (
	// ConsumerTool: the task's tool, through its declared slot.
	ConsumerTool = "tool"
	// ConsumerForwarder: the sensor's egress forwarder of the job.
	ConsumerForwarder = "forwarder"
)

// ConsumerOf is the consumer of a known kind ("" for an unknown kind).
func ConsumerOf(kind string) string {
	switch kind {
	case KindProviderKey:
		return ConsumerTool
	case KindEgressProxy:
		return ConsumerForwarder
	}
	return ""
}

// Local policies: whether a value the sensor's operator stored locally may
// fill a slot. The sensor applies LocalNever regardless of the job when its
// own identity says it is a shared sensor.
const (
	// LocalAllow: the platform's value wins; the local value fills the slot
	// when the platform has none (the organization's own sensor).
	LocalAllow = "allow"
	// LocalNever: only the platform's value; the local value is never used
	// (a shared sensor: its operator's keys are never spent on a tenant).
	LocalNever = "never"
	// LocalOnly: the platform is not asked; only the local value is used.
	LocalOnly = "only"
)

func knownLocal(l string) bool { return l == LocalAllow || l == LocalNever || l == LocalOnly }

// Audiences. A provider key's audience is AudienceProviderPrefix + its
// provider id; the egress pool's audience is AudiencePool (the forwarder
// sends the credentials to the pool's endpoints only); a target credential's
// audience is AudienceTargets (the task's own targets that are also in the
// credential's asset binding).
const (
	AudienceProviderPrefix = "provider:"
	AudiencePool           = "pool"
	AudienceTargets        = "targets"
)

// AudienceProvider is the audience of provider id's key.
func AudienceProvider(id string) string { return AudienceProviderPrefix + id }

// Bounds.
const (
	// MaxRefs is the most refs one job carries.
	MaxRefs = 64
	// MaxRefLen bounds Ref.Ref.
	MaxRefLen = 128
	// MaxTaskLen bounds FetchRequest.Task.
	MaxTaskLen = 64
)

// Refusal and missing reasons.
const (
	// RefusalKindUnsupported is the reason a sensor refuses a job with a
	// required ref of a kind it does not know.
	RefusalKindUnsupported = "secret_kind_unsupported"
	// RefusalSecretMissing is the reason a task fails when a required ref
	// has no value.
	RefusalSecretMissing = "secret_missing"
)

// Missing reasons (Missing.Reason): why the platform holds no value for a
// ref it was asked for.
const (
	MissingDisabled       = "disabled"
	MissingNotSet         = "not_set"
	MissingQuotaExhausted = "quota_exhausted"
	MissingUndecryptable  = "undecryptable"
	MissingNotTrusted     = "not_trusted"
)

// KnownMissing reports whether reason is a missing reason of this version.
func KnownMissing(reason string) bool {
	switch reason {
	case MissingDisabled, MissingNotSet, MissingQuotaExhausted, MissingUndecryptable, MissingNotTrusted:
		return true
	}
	return false
}

// ErrInvalid is wrapped by every validation error of this package. Errors
// never repeat a secret value.
var ErrInvalid = errors.New("secretref: invalid")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9]{1,8}$`)
	slotPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	refPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	taskPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

// ValidID reports whether id is a valid ref id (1 to 8 lower-case letters
// or digits).
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Ref is one secret a job may use. It names a value, never carries one.
type Ref struct {
	// ID is the ref's id within the job (1 to 8 lower-case letters or
	// digits), what a FetchRequest names.
	ID string `json:"id"`
	// Kind is the secret kind (Kind* constants).
	Kind string `json:"kind"`
	// Class is the kind's class (Class* constants): ClassOf a known kind.
	Class string `json:"class"`
	// Ref names the stored value: the provider id for KindProviderKey, the
	// pool id for KindEgressProxy.
	Ref string `json:"ref"`
	// Slot is the tool's credential slot the value fills (the name the
	// tool's manifest declares); empty for a forwarder kind.
	Slot string `json:"slot,omitempty"`
	// Audience is where the value may be sent (Audience* forms).
	Audience []string `json:"audience,omitempty"`
	// Consumer is who receives the value (ConsumerOf the kind).
	Consumer string `json:"consumer"`
	// Required: the task fails, naming the slot, when the value is missing.
	Required bool `json:"required,omitempty"`
	// Local is the local policy of this slot (Local* constants).
	Local string `json:"local"`
}

// Validate checks a ref: the id, kind-independent bounds and, for a known
// kind, the kind's own rules. An unknown kind passes when the generic rules
// hold; whether to use it is the sensor's decision (RefusalKindUnsupported).
func (r Ref) Validate() error {
	if !ValidID(r.ID) {
		return invalid("ref id must be 1 to 8 lower-case letters or digits")
	}
	if r.Kind == "" || len(r.Kind) > 64 || !slotPattern.MatchString(r.Kind) {
		return invalid("ref %s: invalid kind", r.ID)
	}
	if !KnownClass(r.Class) || (KnownKind(r.Kind) && ClassOf(r.Kind) != r.Class) {
		return invalid("ref %s: invalid class", r.ID)
	}
	if r.Ref == "" || len(r.Ref) > MaxRefLen || !refPattern.MatchString(r.Ref) {
		return invalid("ref %s: invalid ref", r.ID)
	}
	if r.Slot != "" && !slotPattern.MatchString(r.Slot) {
		return invalid("ref %s: invalid slot", r.ID)
	}
	if !knownLocal(r.Local) {
		return invalid("ref %s: local must be allow, never or only", r.ID)
	}
	if len(r.Audience) > 16 {
		return invalid("ref %s: too many audiences", r.ID)
	}
	for _, a := range r.Audience {
		if a == "" || len(a) > 128 || strings.ContainsAny(a, " \t\r\n") {
			return invalid("ref %s: invalid audience", r.ID)
		}
	}
	switch r.Kind {
	case KindProviderKey:
		if _, ok := LookupProvider(r.Ref); !ok {
			return invalid("ref %s: unknown provider", r.ID)
		}
		if r.Slot == "" || r.Consumer != ConsumerTool {
			return invalid("ref %s: a provider key fills a tool slot", r.ID)
		}
		if len(r.Audience) != 1 || r.Audience[0] != AudienceProvider(r.Ref) {
			return invalid("ref %s: a provider key's audience is its provider", r.ID)
		}
	case KindEgressProxy:
		if r.Slot != "" || r.Consumer != ConsumerForwarder {
			return invalid("ref %s: the proxy pool's credentials go to the forwarder only", r.ID)
		}
		if len(r.Audience) != 1 || r.Audience[0] != AudiencePool {
			return invalid("ref %s: the proxy pool's audience is the pool", r.ID)
		}
		if r.Local != LocalNever {
			return invalid("ref %s: the proxy pool's credentials have no local value", r.ID)
		}
	default:
		if r.Consumer != ConsumerTool && r.Consumer != ConsumerForwarder {
			return invalid("ref %s: invalid consumer", r.ID)
		}
		// A target credential is sent only to the task's targets, and is
		// chosen by a person, so it always fills a named slot.
		if r.Class == ClassTarget && (r.Consumer != ConsumerTool || r.Slot == "" ||
			len(r.Audience) != 1 || r.Audience[0] != AudienceTargets) {
			return invalid("ref %s: a target credential fills a tool slot and goes to the targets only", r.ID)
		}
	}
	return nil
}

// Set is the payload member PayloadField of a job: the refs the job may use.
type Set struct {
	// V is Version.
	V int `json:"v"`
	// Local is the local policy of a tool slot no ref names: LocalAllow on
	// the organization's own sensor, LocalNever on a shared sensor. It is
	// never LocalOnly.
	Local string `json:"local"`
	// Refs are the job's refs, at most MaxRefs, ids unique.
	Refs []Ref `json:"refs"`
}

// Validate checks the set and each ref.
func (s Set) Validate() error {
	if s.V != Version {
		return invalid("unsupported secrets version %d", s.V)
	}
	if s.Local != LocalAllow && s.Local != LocalNever {
		return invalid("the set's local policy must be allow or never")
	}
	if len(s.Refs) > MaxRefs {
		return invalid("more than %d refs", MaxRefs)
	}
	ids := make(map[string]bool, len(s.Refs))
	slots := map[string]bool{}
	for _, r := range s.Refs {
		if err := r.Validate(); err != nil {
			return err
		}
		if ids[r.ID] {
			return invalid("duplicate ref id %s", r.ID)
		}
		ids[r.ID] = true
		if r.Slot != "" {
			if slots[r.Slot] {
				return invalid("two refs fill slot %s", r.Slot)
			}
			slots[r.Slot] = true
		}
	}
	return nil
}

// Lookup returns the ref with id.
func (s Set) Lookup(id string) (Ref, bool) {
	for _, r := range s.Refs {
		if r.ID == id {
			return r, true
		}
	}
	return Ref{}, false
}

// ForSlot returns the ref that fills slot.
func (s Set) ForSlot(slot string) (Ref, bool) {
	for _, r := range s.Refs {
		if r.Slot != "" && r.Slot == slot {
			return r, true
		}
	}
	return Ref{}, false
}
