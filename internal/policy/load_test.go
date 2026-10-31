package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestLoadEmptyIsStrictDefaults(t *testing.T) {
	for _, in := range []string{"", "# only a comment\n", "{}"} {
		p, err := Load([]byte(in))
		require.NoError(t, err)
		assert.Equal(t, core.StrictDefaults(), p)
	}
}

func TestLoadFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(testutil.Fixture(t, "php-symfony"), "riskrails.yaml"))
	require.NoError(t, err)
	p, err := Load(b)
	require.NoError(t, err)
	assert.Equal(t, "shop-backend", p.Project.Name)
	assert.Equal(t, core.L2, *p.Autonomy.Ceiling)
	assert.Equal(t, core.TokenCount(3_000_000), p.Models.Budgets[core.ModeFull])
	// absent whole mode entry comes from defaults, present ones are not defaulted attribute-wise
	assert.Equal(t, core.L0, p.Autonomy.ByMode[core.ModeProgramme])
	assert.Nil(t, p.Risk.Modes[core.ModeLight].Min)
	// absent field inside a present section comes from defaults
	assert.Equal(t, "ast", p.Enforcement.Commands.Parser)
	assert.Len(t, p.Risk.Axes, 6)
}

func TestLoadPartialKeepsPresentAndFillsRest(t *testing.T) {
	p, err := Load([]byte("autonomy:\n  ceiling: L1\nenforcement:\n  egress:\n    allow: [a.com]\nmodels:\n  effort: {FAST: high}\n"))
	require.NoError(t, err)
	d := core.StrictDefaults()
	assert.Equal(t, core.L1, *p.Autonomy.Ceiling)
	assert.Equal(t, d.Autonomy.ByMode, p.Autonomy.ByMode)
	assert.Equal(t, []string{"a.com"}, p.Enforcement.Egress.Allow)
	assert.True(t, *p.Enforcement.Egress.DenyDefault)
	assert.Equal(t, "high", p.Models.Effort[core.TierFast])
	assert.Equal(t, "medium", p.Models.Effort[core.TierBalanced]) // missing key filled
}

func TestLoadExplicitEmptyListIsKept(t *testing.T) {
	p, err := Load([]byte("risk:\n  hot_paths: []\n"))
	require.NoError(t, err)
	assert.Empty(t, p.Risk.HotPaths)
}

func TestLoadRejects(t *testing.T) {
	for name, in := range map[string]string{
		"unknown top":          "bogus: 1",
		"unknown in map":       "risk: {axes: {scope: {bogus: 1}}}",
		"unknown in slice":     "verify: {adapters: [{name: a, cmd: b, bogus: 1}]}",
		"fail_closed false":    "enforcement: {fail_closed: false}",
		"remote in project":    "remote: owner/repo",
		"effort value":         "models: {effort: {FAST: max}}",
		"measured value":       "risk: {axes: {scope: {measured: vibes}}}",
		"rescore direction":    "risk: {rescore: {direction: down}}",
		"autonomy output":      "autonomy: {output: merge}",
		"commands parser":      "enforcement: {commands: {parser: regex}}",
		"kill switch on read":  "autonomy: {kill_switch: {on_read_error: continue}}",
		"schema":               "schema: 2",
		"two documents":        "schema: 1\n---\nschema: 1\n",
		"bad yaml":             "a: [",
		"max_wall zero":        "autonomy: {unattended: {max_wall_minutes: 0}}",
		"max_tasks negative":   "autonomy: {unattended: {max_tasks_per_day: -1}}",
		"poll zero":            "autonomy: {kill_switch: {poll_seconds: 0}}",
		"ttl zero":             "models: {probe: {ttl_hours: 0}}",
		"suite_budget zero":    "verify: {suite_budget: 0}",
		"budget zero":          "models: {budgets: {light: 0}}",
		"scout budget zero":    "research: {budget_per_scout: 0}",
		"bands negative":       "risk: {axes: {scope: {bands: [-1, 5]}}}",
		"bands not increasing": "risk: {axes: {scope: {bands: [3, 3]}}}",
		"mode negative":        "risk: {modes: {light: {max: -1}}}",
		"mode min above max":   "risk: {modes: {guarded: {min: 5, max: 2}}}",
		"invalid glob":         "risk: {hot_paths: [\"[\"]}",
		"dot-slash glob":       "risk: {hot_paths: [\"./x\"]}",
		"trailing slash glob":  "enforcement: {protected_paths: [\"x/\"]}",
		"empty glob":           "enforcement: {secret_reads: [\"\"]}",
		"bad test glob":        "risk: {axes: {coverage: {test_globs: [\"./t\"]}}}",
		"bad domain glob":      "risk: {domain: {money: [\"x/\"]}}",
		"bad no_write glob":    "enforcement: {sandbox: {no_write: [\"./a\"]}}",
		"invalid sandbox glob": "enforcement: {sandbox: {no_read: [\"a[\"]}}",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(in))
			assert.Error(t, err)
		})
	}
}

func TestLoadCeiling(t *testing.T) {
	p, err := LoadCeiling([]byte("remote: acme/shop\nautonomy: {ceiling: L1}\n"))
	require.NoError(t, err)
	assert.Equal(t, "acme/shop", p.Remote)
	assert.Equal(t, core.L1, *p.Autonomy.Ceiling)
	// no defaults: everything else is absent
	assert.Nil(t, p.Enforcement.FailClosed)
	assert.Nil(t, p.Risk.Axes)
	assert.Zero(t, p.Schema)

	empty, err := LoadCeiling(nil)
	require.NoError(t, err)
	assert.Equal(t, core.Policy{}, empty)

	for _, in := range []string{"enforcement: {protected_paths: [\"./x\"]}", "enforcement: {sandbox: {readonly: [\"x/\"]}}", "bogus: 1", "enforcement: {fail_closed: false}", "schema: 3", "autonomy: {output: merge}"} {
		_, err := LoadCeiling([]byte(in))
		assert.Error(t, err, in)
	}
}
