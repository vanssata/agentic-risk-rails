// Package research is the research factory (DES §5): scout roles and briefs,
// output parsing, deterministic merge, commit-SHA cache, and scout launching.
package research

import (
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Roles are the six scout roles of DES §5.2 (policy names; worker role is name+"-scout").
var Roles = []string{"code", "test", "project-docs", "tech-docs", "prior-art", "history"}

// WorkerRole is the core.WorkerSpec.Role of a scout.
func WorkerRole(role string) string { return role + "-scout" }

func validRole(r string) bool {
	for _, x := range Roles {
		if x == r {
			return true
		}
	}
	return false
}

// RolesFor returns the scouts of a mode from the policy (DES §5.3). full_irreversible
// researches like full when the policy does not list it.
func RolesFor(spec core.ResearchSpec, mode core.Mode) ([]string, error) {
	rs, ok := spec.ByMode[mode]
	if !ok && mode == core.ModeFullIrreversible {
		rs, ok = spec.ByMode[core.ModeFull]
	}
	if !ok {
		return nil, fmt.Errorf("research: no scouts configured for mode %q", mode)
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		if !validRole(r) {
			return nil, fmt.Errorf("research: unknown role %q", r)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}
