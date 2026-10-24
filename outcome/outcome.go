// Package outcome is the per-target outcome of a scan task: how each of the
// task's targets ended. A sensor reports one outcome per target when a task
// ends (completed, partial or stopped part-way); the platform settles every
// target that has an outcome and hands only the unfinished ones out again,
// so a task that stopped after part of its work never runs the finished
// targets a second time.
//
// States:
//
//   - done: the target was scanned (whatever it found, nothing included);
//   - failed: the tool tried the target and it failed, with a class:
//     unreachable (no answer, no route, no name), timeout (the target's own
//     time budget ran out), tool_error (the tool failed on that target) or
//     egress_refused (the sensor's network confinement refused every
//     connection the tool made toward the target: it was not reached, and
//     nothing can be said about it);
//   - skipped: the target was not run on purpose, with a class: refused (a
//     policy refused it) or excluded (the job's exclusions cover it);
//   - unfinished: the task stopped before the target got an outcome.
//
// Revision 2 adds classes that tell why a target was not covered, so the
// platform does not read a fact about the target as a failure of the scan:
//
//   - name_gone: the name no longer exists (an authoritative NXDOMAIN or
//     NODATA answer);
//   - resolver_failed: the name could not be resolved (SERVFAIL, REFUSED, a
//     resolver timeout): ambiguous, it may be the sensor's own DNS;
//   - sensor_network_fault: the sensor's own network failed the control
//     probe, so nothing can be said about the target;
//   - rate_limited: the target asked the scan to slow down and the task
//     could not finish at the rate it allowed;
//   - edge_challenged and edge_blocked: an edge protection (a WAF or CDN)
//     answered with a challenge or a block in place of the service, so the
//     service was not scanned. Failed when the edge started answering during
//     the task, skipped when the task did not run the target because of it.
//
// A target also carries an optional cause side (target, sensor or platform),
// a short reason for an unreachable target (no_route, filtered, host_down,
// ...) and the edge vendor. They are additive: a receiver that does not know
// them ignores them, and Legacy gives the entry a receiver of revision 1
// accepts. A sensor sends revision 2 entries only to a platform that
// advertised them; an entry with a class the receiver does not know is never
// read as done.
//
// Done, failed and skipped settle a target: retrying it would give the same
// answer, so it is not handed out again in the same run. Unfinished is the
// only state that asks for another attempt.
//
// The platform never trusts a sensor's list as is. Normalize reads it
// against the task's own target list: a target the task does not carry is
// dropped (a sensor can never add work), an entry with an unknown state or
// class is ignored, and a task target with no valid entry is unfinished.
//
// The package is part of the CTIS contract (standard library only): the
// platform and the sensor SDK both import it, so neither depends on the
// other for this shape.
package outcome

// Revision is the revision of this contract: 1 is the original states and
// classes, 2 adds the classes, cause, reason and vendor described above. A
// platform advertises the revision it accepts; a sensor sends no newer one.
const Revision = 2

// ResultKey is the member of a command result (and the property of a CTIS
// report) that carries the task's per-target outcomes.
const ResultKey = "target_outcomes"

// MaxTargets bounds the outcomes one result may carry; Normalize reads no
// more entries than this.
const MaxTargets = 100000

// MaxTargetLen bounds one target value in an outcome.
const MaxTargetLen = 2048

// State is how a target ended.
type State string

// States.
const (
	Done       State = "done"
	Failed     State = "failed"
	Skipped    State = "skipped"
	Unfinished State = "unfinished"
)

// Class says why a target failed or was skipped.
type Class string

// Classes of a failed target.
const (
	Unreachable Class = "unreachable"
	Timeout     Class = "timeout"
	ToolError   Class = "tool_error"
	// EgressRefused: the sensor's own egress confinement refused every
	// connection toward the target. It settles the target like the other
	// failures (the same sensor would refuse it again); a receiver shows it
	// as "not reached", never as "nothing found".
	EgressRefused Class = "egress_refused"
)

// Classes of a failed target added in revision 2.
const (
	// NameGone: the name does not exist any more (authoritative NXDOMAIN or
	// NODATA). A fact about the target.
	NameGone Class = "name_gone"
	// ResolverFailed: the name could not be resolved (SERVFAIL, REFUSED, a
	// resolver timeout). Ambiguous: the resolver may be the sensor's.
	ResolverFailed Class = "resolver_failed"
	// SensorNetworkFault: the sensor's own network failed the control probe.
	// A fault of the sensor, never a fact about the target.
	SensorNetworkFault Class = "sensor_network_fault"
	// RateLimited: the target pushed back and the task could not finish at
	// the rate it allowed.
	RateLimited Class = "rate_limited"
)

// Classes of a failed or skipped target added in revision 2: an edge
// protection answered in place of the service.
const (
	EdgeChallenged Class = "edge_challenged"
	EdgeBlocked    Class = "edge_blocked"
)

// Classes of a skipped target.
const (
	Refused  Class = "refused"
	Excluded Class = "excluded"
)

// Cause says whose side a not-covered target is on. Only sensor and platform
// causes are faults of the scan; a target-side outcome is an observation about
// the asset.
type Cause string

// Causes.
const (
	CauseTarget   Cause = "target"
	CauseSensor   Cause = "sensor"
	CausePlatform Cause = "platform"
)

// Bounds of the free-form members of a Target.
const (
	MaxReasonLen = 64
	MaxVendorLen = 32
)

// Target is one target's outcome. Cause, Reason and Vendor are optional
// (revision 2): Reason refines an unreachable target (no_route, filtered,
// host_down, ...) and Vendor names the edge that answered in its place.
type Target struct {
	Target string `json:"target"`
	State  State  `json:"state"`
	Class  Class  `json:"class,omitempty"`
	Cause  Cause  `json:"cause,omitempty"`
	Reason string `json:"reason,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

// failedClasses and skippedClasses are the classes each state takes.
func failedClass(c Class) bool {
	switch c {
	case Unreachable, Timeout, ToolError, EgressRefused,
		NameGone, ResolverFailed, SensorNetworkFault, RateLimited, EdgeChallenged, EdgeBlocked:
		return true
	}
	return false
}

func skippedClass(c Class) bool {
	switch c {
	case Refused, Excluded, EdgeChallenged, EdgeBlocked:
		return true
	}
	return false
}

// validCause reports whether c is empty or a known cause.
func validCause(c Cause) bool {
	return c == "" || c == CauseTarget || c == CauseSensor || c == CausePlatform
}

// token reports whether s is a short lower-case identifier (letters, digits,
// underscore, dash, dot) of at most max bytes: free-form members come from a
// sensor, so they are never carried as arbitrary text.
func token(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// Side is the cause side of the outcome: the reported Cause when it is
// valid, else the one its class implies (sensor_network_fault is the
// sensor's; a refused or excluded target is the platform's policy; every
// other failed or skipped class is a fact about the target; done and
// unfinished have none).
func (t Target) Side() Cause {
	if validCause(t.Cause) && t.Cause != "" {
		return t.Cause
	}
	switch t.State {
	case Failed:
		switch t.Class {
		case SensorNetworkFault:
			return CauseSensor
		case ToolError, EgressRefused:
			return CausePlatform
		}
		return CauseTarget
	case Skipped:
		if t.Class == Refused || t.Class == Excluded {
			return CausePlatform
		}
		return CauseTarget
	}
	return ""
}

// Fault reports whether the outcome is a fault of the scan (a sensor or
// platform cause) and not an observation about the target.
func (t Target) Fault() bool {
	s := t.Side()
	return s == CauseSensor || s == CausePlatform
}

// Legacy returns the entry as a receiver of revision 1 accepts it: a class it
// does not know becomes the closest one it does, and the added members are
// dropped. The result is still never done, so the target is not read as
// covered.
func (t Target) Legacy() Target {
	switch t.Class {
	case NameGone, ResolverFailed, SensorNetworkFault:
		t.State, t.Class = Failed, Unreachable
	case RateLimited, EdgeChallenged, EdgeBlocked:
		// Not covered, and not "unreachable": the closest class a revision 1
		// receiver has for a target the tool could not finish is a tool
		// error.
		t.State, t.Class = Failed, ToolError
	}
	t.Cause, t.Reason, t.Vendor = "", "", ""
	return t
}

// Valid reports whether the outcome is well formed: a non-empty target of at
// most MaxTargetLen bytes, a known state, and a class that fits it (failed
// and skipped need one of theirs; done and unfinished take none).
func (t Target) Valid() bool {
	if t.Target == "" || len(t.Target) > MaxTargetLen {
		return false
	}
	if !validCause(t.Cause) || !token(t.Reason, MaxReasonLen) || !token(t.Vendor, MaxVendorLen) {
		return false
	}
	switch t.State {
	case Done, Unfinished:
		return t.Class == "" && t.Cause == "" && t.Reason == "" && t.Vendor == ""
	case Failed:
		return failedClass(t.Class)
	case Skipped:
		return skippedClass(t.Class)
	}
	return false
}

// Settled reports whether the outcome settles its target (done, failed or
// skipped): the target is not handed out again in the same run.
func (t Target) Settled() bool {
	return t.Valid() && t.State != Unfinished
}

// Normalize returns exactly one outcome per distinct task target, in task
// order: the first valid entry of reported for that target, else
// unfinished. Entries for targets the task does not carry and invalid
// entries are dropped; at most MaxTargets entries of reported are read.
func Normalize(reported []Target, taskTargets []string) []Target {
	byTarget := make(map[string]Target, min(len(reported), MaxTargets))
	for i, r := range reported {
		if i == MaxTargets {
			break
		}
		if !r.Valid() {
			continue
		}
		if _, seen := byTarget[r.Target]; !seen {
			byTarget[r.Target] = r
		}
	}
	out := make([]Target, 0, len(taskTargets))
	seen := make(map[string]struct{}, len(taskTargets))
	for _, t := range taskTargets {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		if r, ok := byTarget[t]; ok {
			out = append(out, r)
			continue
		}
		out = append(out, Target{Target: t, State: Unfinished})
	}
	return out
}

// Remaining returns the task targets (distinct, in task order) that
// reported does not settle: what is handed out again.
func Remaining(reported []Target, taskTargets []string) []string {
	var out []string
	for _, o := range Normalize(reported, taskTargets) {
		if o.State == Unfinished {
			out = append(out, o.Target)
		}
	}
	return out
}

// Counts is how many targets ended in each state.
type Counts struct {
	Done       int `json:"done"`
	Failed     int `json:"failed"`
	Skipped    int `json:"skipped"`
	Unfinished int `json:"unfinished"`
}

// Count counts the states of outcomes (invalid entries are not counted).
func Count(outcomes []Target) Counts {
	var c Counts
	for _, o := range outcomes {
		if !o.Valid() {
			continue
		}
		switch o.State {
		case Done:
			c.Done++
		case Failed:
			c.Failed++
		case Skipped:
			c.Skipped++
		case Unfinished:
			c.Unfinished++
		}
	}
	return c
}
