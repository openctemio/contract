package capability

import (
	"fmt"
	"strings"
)

// Markdown renders the taxonomy as the reference page docs/capabilities.md.
// A test keeps the committed page equal to this output.
func Markdown() string {
	var b strings.Builder
	b.WriteString("# Capability taxonomy v1\n\n")
	b.WriteString("Generated from `capability/taxonomy.json` by `capability.Markdown()`. Do not edit by hand: run `go test ./capability -run TestMarkdownIsCurrent -update`.\n\n")
	b.WriteString("A capability is an act a scan tool performs. The capability carries the phase, the tier floor, the typed ports, the standard params, the required CTIS output and the framework references; a tool only declares which capabilities it implements. A tool's effective tier is the highest of the capability's floor, the tool's own request and the platform's classification.\n\n")

	b.WriteString("## Phases\n\n| Phase | CTEM stage | Meaning |\n|---|---|---|\n")
	for _, p := range tax.Phases {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", p.ID, p.CTEMStage, p.Description)
	}

	b.WriteString("\n## Port types\n\n| Port | Label | CTIS asset types |\n|---|---|---|\n")
	for _, p := range tax.PortTypes {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", p.Type, p.Label, codeList(p.Carries))
	}

	b.WriteString("\n## Capabilities\n\n| Capability | Status | Phase | Tier floor | In | Out | ATT&CK | D3FEND |\n|---|---|---|---|---|---|---|---|\n")
	for _, c := range tax.Capabilities {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s | %s | T%d | %s | %s | %s | %s |\n",
			c.Ref(), anchor(c.Ref()), c.Status, c.Phase, c.TierFloor,
			portList(c.InPorts), portList(c.OutPorts), plainList(c.ATTACK), plainList(c.D3FEND))
	}

	for _, c := range tax.Capabilities {
		fmt.Fprintf(&b, "\n### %s\n\n%s: %s\n\n", c.Ref(), c.Name, c.Description)
		fmt.Fprintf(&b, "- Status: %s; phase `%s` (CTEM %s); tier floor T%d", c.Status, c.Phase, c.CTEMStage(), c.TierFloor)
		if c.CrossCutting {
			b.WriteString("; cross-cutting (not a workflow node)")
		}
		b.WriteString(".\n")
		fmt.Fprintf(&b, "- Ports: in %s, out %s.\n", portList(c.InPorts), portList(c.OutPorts))
		if len(c.ExtraOutputs) > 0 {
			fmt.Fprintf(&b, "- Also emits: %s.\n", codeList(c.ExtraOutputs))
		}
		if len(c.FindingTypes) > 0 {
			fmt.Fprintf(&b, "- Finding types: %s.\n", codeList(c.FindingTypes))
		}
		if refs := frameworkRefs(c); refs != "" {
			fmt.Fprintf(&b, "- References: %s.\n", refs)
		}
		if d := c.Deprecated; d != nil {
			fmt.Fprintf(&b, "- Deprecated since %s", d.Since)
			if d.ReplacedBy != "" {
				fmt.Fprintf(&b, ", replaced by `%s`", d.ReplacedBy)
			}
			b.WriteString(".\n")
		}
		if len(c.Params) > 0 {
			b.WriteString("\n| Param | Type | Values | Description |\n|---|---|---|---|\n")
			for _, p := range c.Params {
				fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", p.Name, p.Type, paramValues(p), p.Description)
			}
		}
		if len(c.Outputs) > 0 {
			b.WriteString("\nRequired output (every selected record):\n\n")
			for _, r := range c.Outputs {
				b.WriteString("- ")
				if r.Shape != "" {
					fmt.Fprintf(&b, "shape `%s`: ", r.Shape)
				}
				fmt.Fprintf(&b, "`%s`", r.Select)
				if len(r.Paths) > 0 {
					fmt.Fprintf(&b, " carries %s", codeList(r.Paths))
				}
				if len(r.AnyOf) > 0 {
					if len(r.Paths) > 0 {
						b.WriteString(" and")
					}
					fmt.Fprintf(&b, " at least one of %s", codeList(r.AnyOf))
				}
				b.WriteString(".\n")
			}
		}
	}
	return b.String()
}

func frameworkRefs(c Capability) string {
	var parts []string
	if len(c.ATTACK) > 0 {
		parts = append(parts, "ATT&CK "+plainList(c.ATTACK))
	}
	if len(c.D3FEND) > 0 {
		parts = append(parts, "D3FEND "+plainList(c.D3FEND))
	}
	if len(c.CAPEC) > 0 {
		parts = append(parts, plainList(c.CAPEC))
	}
	return strings.Join(parts, "; ")
}

func paramValues(p Param) string {
	switch {
	case len(p.Enum) > 0:
		return codeList(p.Enum)
	case p.Min != nil && p.Max != nil:
		return fmt.Sprintf("%d..%d", *p.Min, *p.Max)
	}
	return ""
}

func anchor(ref string) string {
	return strings.NewReplacer(".", "", "@", "").Replace(ref)
}

func portList(ps []PortType) string {
	if len(ps) == 0 {
		return "none"
	}
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = string(p)
	}
	return codeList(s)
}

func codeList(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return "`" + strings.Join(s, "`, `") + "`"
}

func plainList(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ", ")
}
