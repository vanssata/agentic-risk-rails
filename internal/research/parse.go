package research

import (
	"fmt"
	"strconv"
	"strings"
)

// Fact is one FACTS line. Sources is a list after merge (one entry when parsed).
type Fact struct {
	Claim   string   `json:"claim"`
	Sources []string `json:"sources"`
	Tag     string   `json:"tag"` // [V] or [U]
}

// Report is a parsed scout output (DES §5.4).
type Report struct {
	Role    string   `json:"role,omitempty"`
	Facts   []Fact   `json:"facts"`
	Read    []string `json:"read"`
	Touches []string `json:"touches"`
	Steal   []string `json:"steal"`
	Avoid   []string `json:"avoid"`
	Gaps    []string `json:"gaps"`
	Tokens  int64    `json:"tokens"`
	Calls   int      `json:"calls"`
}

// Parse reads the §5.4 schema line by line. Blank lines are ignored; an unknown
// section, a bullet outside a section or a malformed FACTS/COST line is an error.
func Parse(body string) (Report, error) {
	var r Report
	section := ""
	for i, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fail := func(msg string) (Report, error) { return Report{}, fmt.Errorf("research: line %d: %s", i+1, msg) }
		if !strings.HasPrefix(line, "- ") {
			name, rest, ok := strings.Cut(line, ":")
			if !ok {
				return fail("expected SECTION: or bullet")
			}
			section = name
			rest = strings.TrimSpace(rest)
			switch name {
			case "FACTS", "READ", "TOUCHES", "STEAL", "AVOID", "GAPS":
				if rest != "" {
					return fail("section header must be alone on its line")
				}
			case "COST":
				if _, err := fmt.Sscanf(rest, "tokens=%d calls=%d", &r.Tokens, &r.Calls); err != nil {
					return fail("COST must be tokens=<n> calls=<n>")
				}
			default:
				return fail("unknown section " + strconv.Quote(name))
			}
			continue
		}
		item := strings.TrimSpace(line[2:])
		switch section {
		case "FACTS":
			parts := strings.Split(item, " | ")
			if len(parts) != 3 {
				return fail("FACTS line must be: claim | source | [V]/[U]")
			}
			tag := strings.TrimSpace(parts[2])
			if tag != "[V]" && tag != "[U]" {
				return fail("FACTS tag must be [V] or [U]")
			}
			r.Facts = append(r.Facts, Fact{strings.TrimSpace(parts[0]), []string{strings.TrimSpace(parts[1])}, tag})
		case "READ":
			r.Read = append(r.Read, item)
		case "TOUCHES":
			r.Touches = append(r.Touches, item)
		case "STEAL":
			r.Steal = append(r.Steal, item)
		case "AVOID":
			r.Avoid = append(r.Avoid, item)
		case "GAPS":
			r.Gaps = append(r.Gaps, item)
		default:
			return fail("bullet outside a section")
		}
	}
	return r, nil
}
