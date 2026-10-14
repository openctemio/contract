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
//     time budget ran out) or tool_error (the tool failed on that target);
//   - skipped: the target was not run on purpose, with a class: refused (a
//     policy refused it) or excluded (the job's exclusions cover it);
//   - unfinished: the task stopped before the target got an outcome.
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
)

// Classes of a skipped target.
const (
	Refused  Class = "refused"
	Excluded Class = "excluded"
)

// Target is one target's outcome.
type Target struct {
	Target string `json:"target"`
	State  State  `json:"state"`
	Class  Class  `json:"class,omitempty"`
}

// Valid reports whether the outcome is well formed: a non-empty target of at
// most MaxTargetLen bytes, a known state, and a class that fits it (failed
// and skipped need one of theirs; done and unfinished take none).
func (t Target) Valid() bool {
	if t.Target == "" || len(t.Target) > MaxTargetLen {
		return false
	}
	switch t.State {
	case Done, Unfinished:
		return t.Class == ""
	case Failed:
		return t.Class == Unreachable || t.Class == Timeout || t.Class == ToolError
	case Skipped:
		return t.Class == Refused || t.Class == Excluded
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
