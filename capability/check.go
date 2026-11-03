package capability

import (
	"fmt"
	"strings"
)

// Violation is one way a report misses a capability's contract.
type Violation struct {
	// Kind is "missing_path", "missing_any_of" or "not_allowed".
	Kind string `json:"kind"`
	// Record is the JSON pointer of the record ("/assets/3").
	Record string `json:"record"`
	// Path is the rule path that is missing, or the comma-joined any_of
	// list; for not_allowed, the output kind ("asset:certificate").
	Path string `json:"path"`
}

func (v Violation) String() string {
	switch v.Kind {
	case "not_allowed":
		return fmt.Sprintf("%s: %s is not an output of this capability", v.Record, v.Path)
	case "missing_any_of":
		return fmt.Sprintf("%s: needs one of %s", v.Record, v.Path)
	}
	return fmt.Sprintf("%s: missing %s", v.Record, v.Path)
}

// CheckOptions narrow a check.
type CheckOptions struct {
	// Shape, when set, checks the rules of that shape and the unnamed rules
	// only; other named shapes are skipped.
	Shape string
	// MaxViolations stops the check after this many (default 100), so a
	// hostile report cannot make the result unbounded.
	MaxViolations int
}

// Check reports how a report misses the capability's contract: records the
// capability may not emit, and records that miss a required path. A nil
// result means the report conforms. The report is not modified.
//
// The report is a decoded CTIS JSON document (the form a receiver sees),
// for example the result of json.Unmarshal into a map[string]any. Check is
// a producer and receiver aid: the runtime uses it before upload and the
// platform again at ingest. It does not validate the document against the
// CTIS schema.
func (c Capability) Check(doc map[string]any, opts CheckOptions) ([]Violation, error) {
	if doc == nil {
		return nil, nil
	}
	max := opts.MaxViolations
	if max <= 0 {
		max = 100
	}
	var out []Violation
	full := func() bool { return len(out) >= max }

	typed := func(key, prefix string) {
		recs, _ := doc[key].([]any)
		for i, rec := range recs {
			if full() {
				return
			}
			obj, _ := rec.(map[string]any)
			t, _ := obj["type"].(string)
			if !c.MayEmit(prefix + ":" + t) {
				out = append(out, Violation{Kind: "not_allowed", Record: fmt.Sprintf("/%s/%d", key, i), Path: prefix + ":" + t})
			}
		}
	}
	typed("assets", "asset")
	typed("findings", "finding")
	if deps, _ := doc["dependencies"].([]any); len(deps) > 0 && !c.MayEmit("dependency") && !full() {
		out = append(out, Violation{Kind: "not_allowed", Record: "/dependencies", Path: "dependency"})
	}
	if eps, _ := doc["endpoints"].([]any); len(eps) > 0 && !c.MayEmit("endpoint") && !full() {
		out = append(out, Violation{Kind: "not_allowed", Record: "/endpoints", Path: "endpoint"})
	}

	for _, rule := range c.Outputs {
		if opts.Shape != "" && rule.Shape != "" && rule.Shape != opts.Shape {
			continue
		}
		m := selectRE.FindStringSubmatch(rule.Select)
		if m == nil {
			continue // validated at load
		}
		types := splitTypes(m[2])
		records, _ := doc[m[1]].([]any)
		for i, rec := range records {
			obj, _ := rec.(map[string]any)
			if obj == nil {
				continue
			}
			if len(types) > 0 {
				t, _ := obj["type"].(string)
				if !contains(types, t) {
					continue
				}
			}
			ptr := fmt.Sprintf("/%s/%d", m[1], i)
			for _, p := range rule.Paths {
				if full() {
					return out, nil
				}
				if !present(obj, strings.Split(p, ".")) {
					out = append(out, Violation{Kind: "missing_path", Record: ptr, Path: p})
				}
			}
			if len(rule.AnyOf) > 0 && !full() {
				ok := false
				for _, p := range rule.AnyOf {
					if present(obj, strings.Split(p, ".")) {
						ok = true
						break
					}
				}
				if !ok {
					out = append(out, Violation{Kind: "missing_any_of", Record: ptr, Path: strings.Join(rule.AnyOf, ",")})
				}
			}
		}
	}
	return out, nil
}

// present reports whether the path holds a non-empty value in v.
func present(v any, segs []string) bool {
	if len(segs) == 0 {
		return nonEmpty(v)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	name, list := strings.CutSuffix(segs[0], "[]")
	next, ok := obj[name]
	if !ok {
		return false
	}
	if !list {
		return present(next, segs[1:])
	}
	items, ok := next.([]any)
	if !ok || len(items) == 0 {
		return false
	}
	for _, it := range items {
		if !present(it, segs[1:]) {
			return false
		}
	}
	return true
}

func nonEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(x) != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
