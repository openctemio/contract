// Package tooloption is the shared vocabulary of tool execution options: the
// few knobs almost every scan tool has (per-request timeout, request rate,
// concurrency, retries), defined once so that every tool, the sensor SDK and
// the platform mean the same thing by each name.
//
// A tool declares its options in the configuration schema of its tool
// manifest (tool.yaml "config", the closed JSON Schema subset of the
// settings contract). A property that is one of the common options says so
// with "x-octm-common": "<name>"; its type must be the common option's type
// and its bounds must lie inside the common bounds (CheckProperty). Every
// other property is specific to the tool.
//
// Narrowing. Settings are layered: platform defaults, tenant policy, the
// sensor's configuration, the scan or workflow step, and the platform's
// decision for one job. For an option that narrows down (rate, concurrency,
// retries), a layer closer to the job may only lower the value an earlier
// layer set, never raise it (NarrowValue). The sensor's local policy can lower it
// again. Timeout does not narrow: a scan may wait longer for a slow target,
// within the common bounds and the task's own budget.
//
// Reserved names. How a tool's traffic leaves the sensor (proxy) and how its
// requests identify themselves (user agent, extra headers) are set by the
// platform's egress and HTTP policy, never by a tool option, so a tool may
// not declare a property with one of these names (Reserved).
//
// The package is part of the CTIS contract (standard library only): the
// platform and the sensor SDK both import it, so neither depends on the
// other for what an option means.
package tooloption

import (
	"fmt"
	"math"
	"sort"
)

// Narrowing directions.
const (
	// NarrowNone: any layer may set any value within the bounds.
	NarrowNone = ""
	// NarrowDown: a later layer may only lower the value an earlier layer
	// set.
	NarrowDown = "down"
)

// Units of an option's value.
const (
	UnitSeconds   = "seconds"
	UnitPerSecond = "per_second"
	UnitCount     = "count"
)

// Option is one common option.
type Option struct {
	// Name is the property name a tool uses ("rate").
	Name string `json:"name"`
	// Type is the JSON Schema type of the value; every common option is an
	// integer.
	Type string `json:"type"`
	// Unit of the value.
	Unit string `json:"unit"`
	// Minimum and Maximum bound the value (inclusive). A tool may only
	// narrow them.
	Minimum int64 `json:"minimum"`
	Maximum int64 `json:"maximum"`
	// Narrow is NarrowNone or NarrowDown.
	Narrow string `json:"narrow,omitempty"`
	// Title and Description are the English text; user interfaces look up
	// their own translation by name.
	Title       string `json:"title"`
	Description string `json:"description"`
}

var options = []Option{
	{
		Name: "timeout", Type: "integer", Unit: UnitSeconds, Minimum: 1, Maximum: 300,
		Title:       "Request timeout",
		Description: "Seconds the tool waits for one request or probe to a target before it counts as unanswered.",
	},
	{
		Name: "rate", Type: "integer", Unit: UnitPerSecond, Minimum: 1, Maximum: 100000, Narrow: NarrowDown,
		Title:       "Rate limit",
		Description: "Most requests or packets per second the tool sends across all of its targets.",
	},
	{
		Name: "concurrency", Type: "integer", Unit: UnitCount, Minimum: 1, Maximum: 1000, Narrow: NarrowDown,
		Title:       "Concurrency",
		Description: "Most targets or requests the tool works on at the same time.",
	},
	{
		Name: "retries", Type: "integer", Unit: UnitCount, Minimum: 0, Maximum: 10, Narrow: NarrowDown,
		Title:       "Retries",
		Description: "Times the tool repeats a request that got no answer before it gives up on it.",
	},
}

// reserved are the names no tool option may use.
var reserved = map[string]string{
	"proxy":      "set by the platform's egress policy",
	"user_agent": "set by the platform's HTTP policy",
	"headers":    "set by the platform's HTTP policy",
}

// All returns the common options, sorted by name.
func All() []Option {
	out := append([]Option(nil), options...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns the common option named name.
func Lookup(name string) (Option, bool) {
	for _, o := range options {
		if o.Name == name {
			return o, true
		}
	}
	return Option{}, false
}

// Reserved reports whether name may not be a tool option, and why.
func Reserved(name string) (string, bool) {
	why, ok := reserved[name]
	return why, ok
}

// CheckProperty checks that a tool's property declared as this option is
// compatible with it: the same type, and bounds (when given) inside the
// common bounds. A property without bounds takes the common ones.
func (o Option) CheckProperty(typ string, minimum, maximum *float64) error {
	if typ != o.Type {
		return fmt.Errorf("common option %q is of type %q, not %q", o.Name, o.Type, typ)
	}
	if minimum != nil && (*minimum < float64(o.Minimum) || *minimum > float64(o.Maximum)) {
		return fmt.Errorf("common option %q: minimum %v is outside %d..%d", o.Name, *minimum, o.Minimum, o.Maximum)
	}
	if maximum != nil && (*maximum > float64(o.Maximum) || *maximum < float64(o.Minimum)) {
		return fmt.Errorf("common option %q: maximum %v is outside %d..%d", o.Name, *maximum, o.Minimum, o.Maximum)
	}
	if minimum != nil && maximum != nil && *minimum > *maximum {
		return fmt.Errorf("common option %q: minimum %v is above maximum %v", o.Name, *minimum, *maximum)
	}
	return nil
}

// InBounds reports whether v is a whole number inside the common bounds.
func (o Option) InBounds(v float64) bool {
	return v == math.Trunc(v) && v >= float64(o.Minimum) && v <= float64(o.Maximum)
}

// NarrowValue returns the value a later layer's value comes to, given the value
// an earlier layer set: for an option that narrows down, the lower of the
// two; otherwise the later value. ok is false when the later value had to be
// lowered (callers that validate refuse it; callers that run clamp to the
// returned value).
func (o Option) NarrowValue(earlier, later float64) (value float64, ok bool) {
	if o.Narrow == NarrowDown && later > earlier {
		return earlier, false
	}
	return later, true
}
