package core_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func decodeStrict(t *testing.T, b []byte) (core.Policy, error) {
	t.Helper()
	var p core.Policy
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	err := dec.Decode(&p)
	return p, err
}

// The DES §3.2 example is the schema contract: every key must map to a field.
func TestDESExampleParsesStrictly(t *testing.T) {
	b, err := os.ReadFile(testutil.Fixture(t, "php-symfony/riskrails.yaml"))
	require.NoError(t, err)
	p, err := decodeStrict(t, b)
	require.NoError(t, err)

	assert.Equal(t, 1, p.Schema)
	assert.Equal(t, "main", p.Project.DefaultBranch)
	assert.Len(t, p.Risk.Axes, 6)
	assert.Equal(t, []int{0, 5}, p.Risk.Axes[core.AxisScope].Bands)
	assert.Equal(t, 1, *p.Risk.Axes[core.AxisNovelty].ManifestFloor)
	assert.Equal(t, 8, *p.Risk.Modes[core.ModeFull].Min)
	assert.Equal(t, core.ModeFullIrreversible, p.Risk.HardFloors[2].Mode)
	assert.Equal(t, []core.Axis{core.AxisReversibility, core.AxisDomain}, p.Risk.HardFloors[2].Both)

	assert.Equal(t, []core.Tier{core.TierFast, core.TierBalanced, core.TierStrong}, p.Models.TiersAllowed)
	assert.Equal(t, []string{"fable"}, p.Models.ByRuntime["claude"][core.TierExpert])
	assert.Equal(t, core.TierStrong, p.Models.Ladder.Missing[core.TierExpert])
	assert.Equal(t, core.TokenCount(150_000), p.Models.Budgets[core.ModeLight])
	assert.Equal(t, core.TokenCount(10_000_000), p.Models.Budgets[core.ModeProgramme])

	assert.Equal(t, core.L2, *p.Autonomy.Ceiling)
	assert.Equal(t, core.L0, p.Autonomy.ByMode[core.ModeFullIrreversible])
	assert.Equal(t, core.Ask, *p.Enforcement.Commands.Unlisted)
	assert.Equal(t, core.L2, *p.Enforcement.Sandbox.RequiredFrom)
	assert.True(t, *p.Enforcement.FailClosed)
	assert.Equal(t, core.TokenCount(80_000), *p.Research.BudgetPerScout)
	assert.False(t, *p.Research.TechDocs.Context7)
}

func TestStrictRejectsUnknownKey(t *testing.T) {
	_, err := decodeStrict(t, []byte("schema: 1\nautonomy:\n  ceilling: L2\n"))
	assert.Error(t, err)
}

func TestEnumValidation(t *testing.T) {
	for _, bad := range []string{
		"autonomy:\n  ceiling: L5\n",
		"models:\n  tiers_allowed: [TURBO]\n",
		"enforcement:\n  commands:\n    unlisted: maybe\n",
		"risk:\n  hard_floors: [{axis: scope, value: 2, mode: extreme}]\n",
		"models:\n  budgets: {light: 1.5k}\n",
		"risk:\n  axes: {scoep: {measured: refs}}\n",
		"risk:\n  policy_file_weight: {behavior: 2}\n",
		"risk:\n  hard_floors: [{axis: domian, value: 2, mode: full}]\n",
	} {
		_, err := decodeStrict(t, []byte(bad))
		assert.Error(t, err, bad)
	}
}

func TestOrdering(t *testing.T) {
	assert.Equal(t, core.Deny, core.Stricter(core.Allow, core.Deny))
	assert.Equal(t, core.Ask, core.Stricter(core.Ask, core.Allow))
	assert.Less(t, core.ModeGuarded.Rank(), core.ModeFull.Rank())
	assert.Less(t, core.TierFast.Rank(), core.TierExpert.Rank())
	assert.Equal(t, "L3", core.L3.String())
}
