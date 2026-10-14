package tooloption

import (
	"regexp"
	"testing"
)

func f(v float64) *float64 { return &v }

func TestAllSortedAndWellFormed(t *testing.T) {
	name := regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	all := All()
	if len(all) == 0 {
		t.Fatal("no common options")
	}
	for i, o := range all {
		if i > 0 && all[i-1].Name >= o.Name {
			t.Errorf("not sorted at %q", o.Name)
		}
		if !name.MatchString(o.Name) {
			t.Errorf("%q is not a setting name", o.Name)
		}
		if o.Type != "integer" || o.Minimum > o.Maximum || o.Title == "" || o.Description == "" {
			t.Errorf("%q is malformed: %+v", o.Name, o)
		}
		if o.Narrow != NarrowNone && o.Narrow != NarrowDown {
			t.Errorf("%q: unknown narrowing %q", o.Name, o.Narrow)
		}
		if _, r := Reserved(o.Name); r {
			t.Errorf("%q is both common and reserved", o.Name)
		}
	}
	// All returns a copy.
	all[0].Name = "changed"
	if All()[0].Name == "changed" {
		t.Error("All shares its backing array")
	}
}

func TestLookup(t *testing.T) {
	for _, n := range []string{"timeout", "rate", "concurrency", "retries"} {
		if _, ok := Lookup(n); !ok {
			t.Errorf("%s missing", n)
		}
	}
	if _, ok := Lookup("threads"); ok {
		t.Error("unknown option found")
	}
}

func TestReserved(t *testing.T) {
	for _, n := range []string{"proxy", "user_agent", "headers"} {
		if why, ok := Reserved(n); !ok || why == "" {
			t.Errorf("%s should be reserved with a reason", n)
		}
	}
	if _, ok := Reserved("rate"); ok {
		t.Error("rate is not reserved")
	}
}

func TestCheckProperty(t *testing.T) {
	rate, _ := Lookup("rate")
	cases := []struct {
		name     string
		typ      string
		min, max *float64
		ok       bool
	}{
		{"no bounds", "integer", nil, nil, true},
		{"narrower", "integer", f(1), f(5000), true},
		{"wrong type", "string", nil, nil, false},
		{"number is not integer", "number", nil, nil, false},
		{"max above", "integer", nil, f(1e6), false},
		{"min below", "integer", f(0), nil, false},
		{"min above max", "integer", f(50), f(10), false},
		{"max below common min", "integer", nil, f(0), false},
	}
	for _, c := range cases {
		err := rate.CheckProperty(c.typ, c.min, c.max)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestInBounds(t *testing.T) {
	retries, _ := Lookup("retries")
	for v, want := range map[float64]bool{0: true, 10: true, 11: false, -1: false, 1.5: false} {
		if got := retries.InBounds(v); got != want {
			t.Errorf("InBounds(%v) = %v, want %v", v, got, want)
		}
	}
}

func TestNarrowValue(t *testing.T) {
	rate, _ := Lookup("rate")
	if v, ok := rate.NarrowValue(100, 50); !ok || v != 50 {
		t.Errorf("lowering: %v %v", v, ok)
	}
	if v, ok := rate.NarrowValue(100, 500); ok || v != 100 {
		t.Errorf("raising must be refused and clamped: %v %v", v, ok)
	}
	timeout, _ := Lookup("timeout")
	if v, ok := timeout.NarrowValue(10, 30); !ok || v != 30 {
		t.Errorf("timeout does not narrow: %v %v", v, ok)
	}
}
