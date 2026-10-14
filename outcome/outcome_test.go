package outcome

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	cases := []struct {
		o    Target
		want bool
	}{
		{Target{"a", Done, ""}, true},
		{Target{"a", Unfinished, ""}, true},
		{Target{"a", Failed, Unreachable}, true},
		{Target{"a", Failed, Timeout}, true},
		{Target{"a", Failed, ToolError}, true},
		{Target{"a", Skipped, Refused}, true},
		{Target{"a", Skipped, Excluded}, true},
		{Target{"a", Done, Timeout}, false},
		{Target{"a", Unfinished, ToolError}, false},
		{Target{"a", Failed, ""}, false},
		{Target{"a", Failed, Refused}, false},
		{Target{"a", Skipped, Timeout}, false},
		{Target{"a", "ok", ""}, false},
		{Target{"", Done, ""}, false},
		{Target{strings.Repeat("x", MaxTargetLen+1), Done, ""}, false},
	}
	for _, c := range cases {
		if got := c.o.Valid(); got != c.want {
			t.Errorf("Valid(%+v) = %v, want %v", c.o, got, c.want)
		}
	}
	if (Target{"a", Unfinished, ""}).Settled() {
		t.Error("unfinished must not settle")
	}
	if !(Target{"a", Failed, Timeout}).Settled() {
		t.Error("a failed target is settled")
	}
}

func TestNormalize(t *testing.T) {
	task := []string{"a", "b", "c", "d", "a"}
	reported := []Target{
		{"b", Failed, Timeout},
		{"evil.example", Done, ""}, // not a task target: dropped
		{"c", "bogus", ""},         // invalid: c stays unfinished
		{"a", Done, ""},
		{"a", Failed, ToolError}, // later duplicate ignored
	}
	got := Normalize(reported, task)
	want := []Target{
		{"a", Done, ""},
		{"b", Failed, Timeout},
		{"c", Unfinished, ""},
		{"d", Unfinished, ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize = %+v, want %+v", got, want)
	}
	if u := Remaining(reported, task); !reflect.DeepEqual(u, []string{"c", "d"}) {
		t.Fatalf("Remaining = %v", u)
	}
	if c := Count(got); c != (Counts{Done: 1, Failed: 1, Unfinished: 2}) {
		t.Fatalf("Count = %+v", c)
	}
}

func TestNormalizeNeverAddsTargets(t *testing.T) {
	got := Normalize([]Target{{"x", Done, ""}, {"y", Unfinished, ""}}, nil)
	if len(got) != 0 {
		t.Fatalf("outcomes for an empty task: %+v", got)
	}
	if u := Remaining([]Target{{"x", Unfinished, ""}}, []string{"a"}); !reflect.DeepEqual(u, []string{"a"}) {
		t.Fatalf("Remaining = %v", u)
	}
}

func TestNormalizeReadsAtMostMaxTargets(t *testing.T) {
	reported := make([]Target, MaxTargets+1)
	for i := range reported {
		reported[i] = Target{"pad", Done, ""}
	}
	reported[MaxTargets] = Target{"late", Done, ""}
	got := Normalize(reported, []string{"late"})
	if got[0].State != Unfinished {
		t.Fatalf("entry past MaxTargets was read: %+v", got[0])
	}
}

func TestJSONShape(t *testing.T) {
	b, err := json.Marshal([]Target{{"https://a.example", Failed, Unreachable}, {"b", Done, ""}})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"target":"https://a.example","state":"failed","class":"unreachable"},{"target":"b","state":"done"}]`
	if string(b) != want {
		t.Fatalf("json = %s", b)
	}
}
