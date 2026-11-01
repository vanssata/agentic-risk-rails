// Package autonomy computes the autonomy level of a task (DES §8.1) and runs
// the unattended runner (DES §8.2) outside the agent sandbox.
package autonomy

import "github.com/vanssata/agentic-risk-rails/internal/core"

// LevelInput is everything the level of one task depends on.
type LevelInput struct {
	Policy       core.Policy
	Mode         core.Mode
	Irreversible bool             // core.Weight.Irreversible (errata #21)
	Enforcement  core.Enforcement // what actually enforces on this host
	InContainer  bool
}

// covers reports whether capacity l runs mode unattended: L2 light, L3 +guarded,
// L4 +full (never full_irreversible or programme).
func covers(l core.Level, m core.Mode) bool {
	switch m {
	case core.ModeLight:
		return l >= core.L2
	case core.ModeGuarded:
		return l >= core.L3
	case core.ModeFull:
		return l >= core.L4
	}
	return false
}

// TaskLevel is min(ceiling, by_mode[mode]). A level that does not cover the
// mode runs interactively as L1, never silently higher. Missing policy values,
// irreversible work, a host without an OS sandbox (hook_only/ci_only/unknown)
// or a missing container (unattended.container is "required", the only value
// the schema defines) all cap the result. The reason is for the journal.
func TaskLevel(in LevelInput) (core.Level, string) {
	if in.Irreversible || in.Mode == core.ModeFullIrreversible {
		return core.L0, "irreversible"
	}
	a := in.Policy.Autonomy
	byMode, ok := a.ByMode[in.Mode]
	if a.Ceiling == nil || !ok {
		return core.L0, "no ceiling or by_mode entry"
	}
	l := min(*a.Ceiling, byMode)
	if l <= core.L1 {
		return l, "policy"
	}
	if !covers(l, in.Mode) {
		return core.L1, "level " + l.String() + " does not cover mode " + string(in.Mode)
	}
	if in.Enforcement != core.EnforcementSandbox {
		return core.L1, "enforcement " + string(in.Enforcement)
	}
	if !in.InContainer {
		return core.L1, "container required"
	}
	return l, ""
}
