package settings

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const commonSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "rate_limit": {"type": "integer", "maximum": 5000, "default": 150, "x-octm-common": "rate", "x-octm-flag": "-rate-limit", "x-octm-scope": "scan"},
    "concurrency": {"type": "integer", "minimum": 1, "maximum": 100, "x-octm-common": "concurrency", "x-octm-flag": "-c", "x-octm-scope": "scan"},
    "timeout": {"type": "integer", "x-octm-common": "timeout", "x-octm-flag": "-timeout", "x-octm-scope": "scan"},
    "severity": {"type": "array", "items": {"type": "string", "enum": ["low", "high"]}, "x-octm-flag": "-severity", "x-octm-scope": "scan"}
  }
}`

func TestCommonOptionsParsed(t *testing.T) {
	s := MustParseSchema(commonSchema)
	p := s.Property("rate_limit")
	if p.Common != "rate" || p.Flag != "-rate-limit" {
		t.Fatalf("rate_limit = %+v", p)
	}
	// The unbounded side takes the common bound.
	if p.Minimum == nil || *p.Minimum != 1 || *p.Maximum != 5000 {
		t.Fatalf("rate_limit bounds = %v..%v", p.Minimum, p.Maximum)
	}
	if err := s.Validate(map[string]any{"timeout": 301}); err == nil {
		t.Fatal("timeout above the common maximum accepted")
	}
	if err := s.Validate(map[string]any{"rate_limit": 0}); err == nil {
		t.Fatal("rate below the common minimum accepted")
	}
	if err := s.Validate(map[string]any{"rate_limit": 100, "timeout": 30}); err != nil {
		t.Fatal(err)
	}
}

func TestCommonOptionSchemaErrors(t *testing.T) {
	base := func(props string) string {
		return `{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"properties":{` + props + `}}`
	}
	cases := map[string]string{
		"unknown common":     `"x":{"type":"integer","x-octm-common":"threads"}`,
		"wrong type":         `"x":{"type":"string","x-octm-common":"rate"}`,
		"wider bounds":       `"x":{"type":"integer","maximum":1000000,"x-octm-common":"rate"}`,
		"exclusive bound":    `"x":{"type":"integer","exclusiveMaximum":100,"x-octm-common":"rate"}`,
		"declared twice":     `"a":{"type":"integer","x-octm-common":"rate"},"b":{"type":"integer","x-octm-common":"rate"}`,
		"nested common":      `"g":{"type":"object","additionalProperties":false,"properties":{"x":{"type":"integer","x-octm-common":"rate"}}}`,
		"reserved proxy":     `"proxy":{"type":"string"}`,
		"reserved ua":        `"user_agent":{"type":"string"}`,
		"reserved headers":   `"headers":{"type":"array","items":{"type":"string"}}`,
		"flag with space":    `"x":{"type":"integer","x-octm-flag":"-c 5"}`,
		"flag injection":     `"x":{"type":"integer","x-octm-flag":"-config=/etc/x"}`,
		"flag not a flag":    `"x":{"type":"integer","x-octm-flag":"rm"}`,
		"common on the root": ``,
	}
	for name, props := range cases {
		raw := base(props)
		if name == "common on the root" {
			raw = `{"x-octm-schema-version":1,"type":"object","additionalProperties":false,"x-octm-common":"rate","properties":{}}`
		}
		if _, err := ParseSchema([]byte(raw)); err == nil {
			t.Errorf("%s: schema accepted", name)
		}
	}
	// A reserved name inside a group is the group's own key, not a tool option.
	ok := base(`"net":{"type":"object","additionalProperties":false,"properties":{"timeout_s":{"type":"integer"}}}`)
	if _, err := ParseSchema([]byte(ok)); err != nil {
		t.Fatal(err)
	}
}

func TestResolveNarrowsCommonOptions(t *testing.T) {
	s := MustParseSchema(commonSchema)
	// The scan lowers the sensor's rate: allowed.
	ts, err := s.Resolve(
		Layer{Source: SourceSensor, Values: map[string]any{"rate_limit": 100, "timeout": 10}},
		Layer{Source: SourceScan, Values: map[string]any{"rate_limit": 50, "timeout": 60}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ts.Int("rate_limit"); v != 50 || ts.Source("rate_limit") != SourceScan {
		t.Fatalf("rate_limit = %d from %s", v, ts.Source("rate_limit"))
	}
	// Timeout does not narrow.
	if v, _ := ts.Int("timeout"); v != 60 {
		t.Fatalf("timeout = %d", v)
	}
	// A scan raising the sensor's rate is refused, not applied.
	_, err = s.Resolve(
		Layer{Source: SourceSensor, Values: map[string]any{"rate_limit": 100}},
		Layer{Source: SourceScan, Values: map[string]any{"rate_limit": 500}},
	)
	var errs Errors
	if !errors.As(err, &errs) || !slices.Equal(errs.Paths(), []string{"/rate_limit"}) || !strings.Contains(err.Error(), "only lower") {
		t.Fatalf("raise: %v", err)
	}
	// The job decision may lower the scan's value, never raise it.
	if _, err := s.Resolve(
		Layer{Source: SourceTenant, Values: map[string]any{"concurrency": 20}},
		Layer{Source: SourceSensor, Values: map[string]any{"concurrency": 10}},
		Layer{Source: SourceJob, Values: map[string]any{"concurrency": 15}},
	); err == nil {
		t.Fatal("job raised the sensor's concurrency")
	}
	// A tenant cap binds the sensor too.
	if _, err := s.Resolve(
		Layer{Source: SourceTenant, Values: map[string]any{"concurrency": 10}},
		Layer{Source: SourceSensor, Values: map[string]any{"concurrency": 20}},
	); err == nil {
		t.Fatal("sensor raised the tenant's concurrency")
	}
	// Above the tool's default is fine when no layer set a value.
	if _, err := s.Resolve(Layer{Source: SourceScan, Values: map[string]any{"rate_limit": 1000}}); err != nil {
		t.Fatal(err)
	}
}

func TestJobAndTenantLayerScopes(t *testing.T) {
	s := MustParseSchema(testNucleiSchema)
	// A tenant layer may set a sensor-scope key; a job layer may not.
	if _, err := s.Resolve(Layer{Source: SourceTenant, Values: map[string]any{"concurrency": 5}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(Layer{Source: SourceJob, Values: map[string]any{"concurrency": 5}}); err == nil {
		t.Fatal("a job layer set a sensor-scope key")
	}
}
