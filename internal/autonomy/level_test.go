package autonomy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func pol(ceiling core.Level) core.Policy {
	p := core.StrictDefaults()
	p.Autonomy.Ceiling = &ceiling
	p.Autonomy.ByMode = map[core.Mode]core.Level{
		core.ModeLight: core.L2, core.ModeGuarded: core.L3, core.ModeFull: core.L4,
		core.ModeFullIrreversible: core.L0, core.ModeProgramme: core.L4,
	}
	return p
}

func TestTaskLevel(t *testing.T) {
	sb, hook, ci := core.EnforcementSandbox, core.EnforcementHookOnly, core.EnforcementCIOnly
	tests := []struct {
		name string
		in   LevelInput
		want core.Level
	}{
		{"light ceiling L2", LevelInput{pol(core.L2), core.ModeLight, false, sb, true}, core.L2},
		{"light ceiling L4 capped by by_mode", LevelInput{pol(core.L4), core.ModeLight, false, sb, true}, core.L2},
		{"guarded ceiling L2 not covered", LevelInput{pol(core.L2), core.ModeGuarded, false, sb, true}, core.L1},
		{"guarded ceiling L3", LevelInput{pol(core.L3), core.ModeGuarded, false, sb, true}, core.L3},
		{"full ceiling L3 not covered", LevelInput{pol(core.L3), core.ModeFull, false, sb, true}, core.L1},
		{"full ceiling L4", LevelInput{pol(core.L4), core.ModeFull, false, sb, true}, core.L4},
		{"programme never unattended", LevelInput{pol(core.L4), core.ModeProgramme, false, sb, true}, core.L1},
		{"full_irreversible", LevelInput{pol(core.L4), core.ModeFullIrreversible, false, sb, true}, core.L0},
		{"irreversible flag beats mode", LevelInput{pol(core.L4), core.ModeLight, true, sb, true}, core.L0},
		{"irreversible programme", LevelInput{pol(core.L4), core.ModeProgramme, true, sb, true}, core.L0},
		{"ceiling L1", LevelInput{pol(core.L1), core.ModeLight, false, sb, true}, core.L1},
		{"ceiling L0", LevelInput{pol(core.L0), core.ModeLight, false, sb, true}, core.L0},
		{"hook_only caps", LevelInput{pol(core.L4), core.ModeLight, false, hook, true}, core.L1},
		{"ci_only caps", LevelInput{pol(core.L4), core.ModeLight, false, ci, true}, core.L1},
		{"no container", LevelInput{pol(core.L4), core.ModeLight, false, sb, false}, core.L1},
		{"unknown enforcement caps", LevelInput{pol(core.L4), core.ModeLight, false, "", true}, core.L1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, why := TaskLevel(tc.in)
			assert.Equal(t, tc.want, got, why)
		})
	}
	t.Run("missing by_mode entry fails closed", func(t *testing.T) {
		p := pol(core.L4)
		delete(p.Autonomy.ByMode, core.ModeLight)
		got, _ := TaskLevel(LevelInput{p, core.ModeLight, false, sb, true})
		assert.Equal(t, core.L0, got)
	})
	t.Run("nil ceiling fails closed", func(t *testing.T) {
		p := pol(core.L4)
		p.Autonomy.Ceiling = nil
		got, _ := TaskLevel(LevelInput{p, core.ModeLight, false, sb, true})
		assert.Equal(t, core.L0, got)
	})
}
