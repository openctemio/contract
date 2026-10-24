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
		{Target{Target: "a", State: Done}, true},
		{Target{Target: "a", State: Unfinished}, true},
		{Target{Target: "a", State: Failed, Class: Unreachable}, true},
		{Target{Target: "a", State: Failed, Class: Timeout}, true},
		{Target{Target: "a", State: Failed, Class: ToolError}, true},
		{Target{Target: "a", State: Failed, Class: EgressRefused}, true},
		{Target{Target: "a", State: Skipped, Class: EgressRefused}, false},
		{Target{Target: "a", State: Skipped, Class: Refused}, true},
		{Target{Target: "a", State: Skipped, Class: Excluded}, true},
		{Target{Target: "a", State: Done, Class: Timeout}, false},
		{Target{Target: "a", State: Unfinished, Class: ToolError}, false},
		{Target{Target: "a", State: Failed}, false},
		{Target{Target: "a", State: Failed, Class: Refused}, false},
		{Target{Target: "a", State: Skipped, Class: Timeout}, false},
		{Target{Target: "a", State: "ok"}, false},
		{Target{Target: "", State: Done}, false},
		{Target{Target: strings.Repeat("x", MaxTargetLen+1), State: Done}, false},
	}
	for _, c := range cases {
		if got := c.o.Valid(); got != c.want {
			t.Errorf("Valid(%+v) = %v, want %v", c.o, got, c.want)
		}
	}
	if (Target{Target: "a", State: Unfinished}).Settled() {
		t.Error("unfinished must not settle")
	}
	if !(Target{Target: "a", State: Failed, Class: Timeout}).Settled() {
		t.Error("a failed target is settled")
	}
}

func TestNormalize(t *testing.T) {
	task := []string{"a", "b", "c", "d", "a"}
	reported := []Target{
		{Target: "b", State: Failed, Class: Timeout},
		{Target: "evil.example", State: Done}, // not a task target: dropped
		{Target: "c", State: "bogus"},         // invalid: c stays unfinished
		{Target: "a", State: Done},
		{Target: "a", State: Failed, Class: ToolError}, // later duplicate ignored
	}
	got := Normalize(reported, task)
	want := []Target{
		{Target: "a", State: Done},
		{Target: "b", State: Failed, Class: Timeout},
		{Target: "c", State: Unfinished},
		{Target: "d", State: Unfinished},
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
	got := Normalize([]Target{{Target: "x", State: Done}, {Target: "y", State: Unfinished}}, nil)
	if len(got) != 0 {
		t.Fatalf("outcomes for an empty task: %+v", got)
	}
	if u := Remaining([]Target{{Target: "x", State: Unfinished}}, []string{"a"}); !reflect.DeepEqual(u, []string{"a"}) {
		t.Fatalf("Remaining = %v", u)
	}
}

func TestNormalizeReadsAtMostMaxTargets(t *testing.T) {
	reported := make([]Target, MaxTargets+1)
	for i := range reported {
		reported[i] = Target{Target: "pad", State: Done}
	}
	reported[MaxTargets] = Target{Target: "late", State: Done}
	got := Normalize(reported, []string{"late"})
	if got[0].State != Unfinished {
		t.Fatalf("entry past MaxTargets was read: %+v", got[0])
	}
}

func TestJSONShape(t *testing.T) {
	b, err := json.Marshal([]Target{{Target: "https://a.example", State: Failed, Class: Unreachable}, {Target: "b", State: Done}})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"target":"https://a.example","state":"failed","class":"unreachable"},{"target":"b","state":"done"}]`
	if string(b) != want {
		t.Fatalf("json = %s", b)
	}
}

func TestRevision2Classes(t *testing.T) {
	ok := []Target{
		{Target: "a", State: Failed, Class: NameGone, Cause: CauseTarget},
		{Target: "a", State: Failed, Class: ResolverFailed},
		{Target: "a", State: Failed, Class: SensorNetworkFault, Cause: CauseSensor},
		{Target: "a", State: Failed, Class: RateLimited},
		{Target: "a", State: Failed, Class: EdgeChallenged, Vendor: "cloudflare"},
		{Target: "a", State: Skipped, Class: EdgeBlocked, Vendor: "akamai"},
		{Target: "a", State: Failed, Class: Unreachable, Reason: "host_down"},
	}
	for _, o := range ok {
		if !o.Valid() || !o.Settled() {
			t.Errorf("%+v must be valid and settled", o)
		}
	}
	bad := []Target{
		{Target: "a", State: Skipped, Class: NameGone},           // never run on purpose
		{Target: "a", State: Skipped, Class: SensorNetworkFault}, // a fault is not a skip
		{Target: "a", State: Done, Class: ""},                    // placeholder replaced below
		{Target: "a", State: Done, Vendor: "cloudflare"},         // done takes no detail
		{Target: "a", State: Failed, Class: NameGone, Cause: "owner"},
		{Target: "a", State: Failed, Class: EdgeBlocked, Vendor: "Cloud Flare\n"},
		{Target: "a", State: Failed, Class: Unreachable, Reason: strings.Repeat("x", MaxReasonLen+1)},
	}
	bad[2] = Target{Target: "a", State: Unfinished, Cause: CauseTarget}
	for _, o := range bad {
		if o.Valid() {
			t.Errorf("%+v must be invalid", o)
		}
	}
}

func TestUnknownClassIsNeverDone(t *testing.T) {
	// A receiver of any revision drops an entry it cannot read; the target
	// goes back to unfinished, never to done.
	got := Normalize([]Target{{Target: "a", State: Failed, Class: "future_class"}}, []string{"a"})
	if len(got) != 1 || got[0].State != Unfinished {
		t.Fatalf("unknown class must leave the target unfinished, got %+v", got)
	}
}

func TestSideAndFault(t *testing.T) {
	cases := []struct {
		o     Target
		side  Cause
		fault bool
	}{
		{Target{Target: "a", State: Failed, Class: NameGone}, CauseTarget, false},
		{Target{Target: "a", State: Failed, Class: Unreachable}, CauseTarget, false},
		{Target{Target: "a", State: Failed, Class: EdgeBlocked}, CauseTarget, false},
		{Target{Target: "a", State: Failed, Class: SensorNetworkFault}, CauseSensor, true},
		{Target{Target: "a", State: Failed, Class: ToolError}, CausePlatform, true},
		{Target{Target: "a", State: Skipped, Class: Refused}, CausePlatform, true},
		{Target{Target: "a", State: Failed, Class: Timeout, Cause: CauseSensor}, CauseSensor, true},
		{Target{Target: "a", State: Done}, "", false},
	}
	for _, c := range cases {
		if c.o.Side() != c.side || c.o.Fault() != c.fault {
			t.Errorf("%+v: side %q fault %v, want %q %v", c.o, c.o.Side(), c.o.Fault(), c.side, c.fault)
		}
	}
}

func TestLegacyIsAcceptedAndNeverDone(t *testing.T) {
	for _, c := range []Class{NameGone, ResolverFailed, SensorNetworkFault, RateLimited, EdgeChallenged, EdgeBlocked} {
		o := Target{Target: "a", State: Skipped, Class: c, Cause: CauseTarget, Reason: "x", Vendor: "y"}
		if c != EdgeChallenged && c != EdgeBlocked {
			o.State = Failed
		}
		l := o.Legacy()
		if !l.Valid() || l.State == Done || l.Cause != "" || l.Reason != "" || l.Vendor != "" {
			t.Errorf("Legacy(%+v) = %+v", o, l)
		}
		switch l.Class {
		case Unreachable, Timeout, ToolError:
		default:
			t.Errorf("Legacy(%s) gave class %q a revision 1 receiver does not know", c, l.Class)
		}
	}
	if o := (Target{Target: "a", State: Done}); o.Legacy() != o {
		t.Error("Legacy changed a done target")
	}
}

func TestRevision2JSONIsAdditive(t *testing.T) {
	// A revision 1 shaped entry still decodes and the new members are omitted
	// when empty, so an older receiver sees the same bytes as before.
	b, err := json.Marshal(Target{Target: "a", State: Failed, Class: Timeout})
	if err != nil || string(b) != `{"target":"a","state":"failed","class":"timeout"}` {
		t.Fatalf("marshal = %s, %v", b, err)
	}
	var o Target
	if err := json.Unmarshal([]byte(`{"target":"a","state":"failed","class":"edge_blocked","cause":"target","vendor":"fastly"}`), &o); err != nil || !o.Valid() {
		t.Fatalf("decode = %+v, %v", o, err)
	}
}
