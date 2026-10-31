package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func layer(p core.Policy) *core.Layer {
	return &core.Layer{Policy: p, Raw: []byte("raw"), Source: "test"}
}

func resolver() *Service {
	s := New()
	s.Files = func(context.Context) ([]string, error) { return treeFiles, nil }
	return s
}

func TestResolveNoLayersIsStrictDefaults(t *testing.T) {
	ep, err := New().Resolve(context.Background(), core.PolicyLayers{})
	require.NoError(t, err)
	assert.Equal(t, core.StrictDefaults(), ep.Policy)
	assert.Equal(t, core.StrictDefaults(), ep.InForce)
	assert.Empty(t, ep.CeilingSHA)
	assert.Regexp(t, `^[0-9a-f]{64}$`, ep.PolicySHA)
	assert.Empty(t, ep.Clamped)
	assert.Empty(t, ep.Ignored)
}

func TestResolveCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New().Resolve(ctx, core.PolicyLayers{})
	assert.Error(t, err)
}

func TestResolveClampsToPartialCeilings(t *testing.T) {
	project := core.StrictDefaults()
	project.Autonomy.Ceiling = ptr(core.L3)
	project.Enforcement.Egress.Allow = []string{"a.com", "b.com"}
	project.Enforcement.Commands.Allow = []string{"git status"}

	ent, err := LoadCeiling([]byte("remote: acme/shop\nautonomy: {ceiling: L1}\nenforcement: {egress: {allow: [a.com]}}\n"))
	require.NoError(t, err)
	usr, err := LoadCeiling([]byte("autonomy: {ceiling: L2}\nenforcement: {protected_paths: [\"src/**\"]}\nmodels:\n  by_runtime: {claude: {FAST: [haiku]}}\n"))
	require.NoError(t, err)

	ep, err := New().Resolve(context.Background(), core.PolicyLayers{
		Enterprise: &core.Layer{Policy: ent, Raw: []byte("E")}, User: &core.Layer{Policy: usr, Raw: []byte("U")},
		DefaultBranch: layer(project),
	})
	require.NoError(t, err)
	assert.Equal(t, core.L1, *ep.Policy.Autonomy.Ceiling)
	assert.Equal(t, []string{"a.com"}, ep.Policy.Enforcement.Egress.Allow)
	assert.Equal(t, []string{"git status"}, ep.Policy.Enforcement.Commands.Allow, "unconstrained field untouched")
	assert.Contains(t, ep.Policy.Enforcement.ProtectedPaths, "src/**")
	assert.Contains(t, ep.Policy.Enforcement.ProtectedPaths, "riskrails.yaml")
	assert.Equal(t, "acme/shop", ep.Policy.Remote)
	assert.Equal(t, []string{"haiku"}, ep.Policy.Models.ByRuntime["claude"][core.TierFast], "user candidates replace the project's")
	assert.Equal(t, core.L3, *ep.InForce.Autonomy.Ceiling, "InForce is the unclamped default-branch policy")

	assert.Contains(t, ep.Clamped, "autonomy.ceiling (user)")
	assert.Contains(t, ep.Clamped, "autonomy.ceiling (enterprise)")
	assert.Contains(t, ep.Clamped, "enforcement.egress.allow (enterprise)")
	assert.NotContains(t, ep.Clamped, "enforcement.commands.allow (enterprise)")
	assert.NotContains(t, ep.Clamped, "models.by_runtime (user)")

	sum := sha256.Sum256([]byte("EU"))
	assert.Equal(t, hex.EncodeToString(sum[:]), ep.CeilingSHA)
}

func TestResolveEnterpriseByRuntimeBeatsUser(t *testing.T) {
	ent, err := LoadCeiling([]byte("models:\n  by_runtime: {claude: {FAST: [ent-model]}}\n"))
	require.NoError(t, err)
	usr, err := LoadCeiling([]byte("models:\n  by_runtime: {claude: {FAST: [user-model]}}\n"))
	require.NoError(t, err)
	ep, err := New().Resolve(context.Background(), core.PolicyLayers{Enterprise: layer(ent), User: layer(usr)})
	require.NoError(t, err)
	assert.Equal(t, []string{"ent-model"}, ep.Policy.Models.ByRuntime["claude"][core.TierFast])
}

func TestResolveWorkingTree(t *testing.T) {
	def := core.StrictDefaults()
	def.Enforcement.Egress.Allow = []string{"a.com"}

	t.Run("tightening only is applied", func(t *testing.T) {
		wt := copyPolicy(def)
		wt.Enforcement.Egress.Allow = []string{}
		wt.Autonomy.Unattended.MaxTasksPerDay = ptr(3)
		ep, err := resolver().Resolve(context.Background(), core.PolicyLayers{DefaultBranch: layer(def), WorkingTree: layer(wt)})
		require.NoError(t, err)
		assert.Empty(t, ep.Policy.Enforcement.Egress.Allow)
		assert.Equal(t, 3, *ep.Policy.Autonomy.Unattended.MaxTasksPerDay)
		assert.Empty(t, ep.Ignored)
		assert.Equal(t, []string{"a.com"}, ep.InForce.Enforcement.Egress.Allow)
	})

	t.Run("loosening is ignored entirely", func(t *testing.T) {
		wt := copyPolicy(def)
		wt.Enforcement.Egress.Allow = []string{"a.com", "evil.com"}
		wt.Autonomy.Unattended.MaxTasksPerDay = ptr(3) // tightening in a MIXED file is not applied either
		ep, err := resolver().Resolve(context.Background(), core.PolicyLayers{DefaultBranch: layer(def), WorkingTree: layer(wt)})
		require.NoError(t, err)
		assert.Equal(t, []string{"a.com"}, ep.Policy.Enforcement.Egress.Allow)
		assert.Equal(t, 10, *ep.Policy.Autonomy.Unattended.MaxTasksPerDay)
		assert.Equal(t, []string{"enforcement.egress.allow"}, ep.Ignored)
	})

	t.Run("narrowed glob is ignored", func(t *testing.T) {
		d := copyPolicy(def)
		d.Risk.HotPaths = []string{"src/Payment/**"}
		wt := copyPolicy(d)
		wt.Risk.HotPaths = []string{"src/Payment/*.php"}
		ep, err := resolver().Resolve(context.Background(), core.PolicyLayers{DefaultBranch: layer(d), WorkingTree: layer(wt)})
		require.NoError(t, err)
		assert.Equal(t, []string{"src/Payment/**"}, ep.Policy.Risk.HotPaths)
		assert.Equal(t, []string{"risk.hot_paths"}, ep.Ignored)
	})

	t.Run("no file list fails closed", func(t *testing.T) {
		d := copyPolicy(def)
		d.Risk.HotPaths = []string{"src/Payment/**"}
		wt := copyPolicy(d)
		wt.Risk.HotPaths = []string{"src/**"}
		ep, err := New().Resolve(context.Background(), core.PolicyLayers{DefaultBranch: layer(d), WorkingTree: layer(wt)})
		require.NoError(t, err)
		assert.NotEmpty(t, ep.Ignored)
	})
}

func TestResolveDoesNotMutateLayers(t *testing.T) {
	def := core.StrictDefaults()
	ent := core.StrictDefaults()
	ent.Enforcement.Egress.Allow = []string{"x.com"}
	ent.Risk.HotPaths = append(ent.Risk.HotPaths, "extra/**")
	before := copyPolicy(def)
	_, err := New().Resolve(context.Background(), core.PolicyLayers{DefaultBranch: layer(def), Enterprise: layer(ent), WorkingTree: layer(def)})
	require.NoError(t, err)
	assert.Equal(t, before, def)
}

func TestPolicySHAIsStableAndSensitive(t *testing.T) {
	a, err := policySHA(core.StrictDefaults())
	require.NoError(t, err)
	b, err := policySHA(core.StrictDefaults())
	require.NoError(t, err)
	assert.Equal(t, a, b)
	p := core.StrictDefaults()
	p.Autonomy.Ceiling = ptr(core.L1)
	c, err := policySHA(p)
	require.NoError(t, err)
	assert.NotEqual(t, a, c)
}

// ---- property: the effective policy is never looser than a layer ----

var (
	globPool = []string{"riskrails.yaml", ".github/workflows/**", "src/Payment/**", "src/Payment/*.php", "src/**", "migrations/**", ".env*", "config/**"}
	cmdPool  = []string{"git status", "git diff*", "composer install", "php bin/phpunit*", "git push*"}
	hostPool = []string{"a.com", "b.com", "packagist.org", "api.github.com"}
)

func pick(r *rand.Rand, pool []string) []string {
	out := []string{}
	for _, s := range pool {
		if r.Intn(2) == 0 {
			out = append(out, s)
		}
	}
	return out
}

func randPolicy(r *rand.Rand) core.Policy {
	p := core.StrictDefaults()
	p.Risk.HotPaths = pick(r, globPool)
	p.Risk.Reversibility.Irreversible = pick(r, globPool)
	p.Risk.Domain["money"] = pick(r, globPool)
	p.Enforcement.ProtectedPaths = pick(r, globPool)
	p.Enforcement.SecretReads = pick(r, globPool)
	p.Enforcement.Sandbox.Readonly = pick(r, globPool)
	p.Enforcement.Commands.Allow = pick(r, cmdPool)
	p.Enforcement.Commands.Deny = pick(r, cmdPool)
	p.Enforcement.Commands.Ask = pick(r, cmdPool)
	p.Enforcement.Egress.Allow = pick(r, hostPool)
	p.Enforcement.Egress.DenyDefault = ptr(r.Intn(2) == 0)
	p.Enforcement.Commands.Unlisted = ptr([]core.Decision{core.Allow, core.Ask, core.Deny}[r.Intn(3)])
	p.Enforcement.Sandbox.RequiredFrom = ptr(core.Level(r.Intn(5)))
	p.Autonomy.Ceiling = ptr(core.Level(r.Intn(5)))
	p.Autonomy.ByMode[core.ModeLight] = core.Level(r.Intn(5))
	p.Autonomy.Unattended.MaxTasksPerDay = ptr(1 + r.Intn(20))
	p.Models.Budgets[core.ModeFull] = core.TokenCount(1 + r.Intn(5_000_000))
	p.Models.Effort[core.TierFast] = []string{"low", "medium", "high"}[r.Intn(3)]
	p.Models.TiersAllowed = []core.Tier{core.TierFast, core.TierBalanced, core.TierStrong, core.TierExpert}[:1+r.Intn(4)]
	p.Risk.PolicyFileWeight[core.AxisBehaviour] = r.Intn(4)
	p.Risk.Rescore.When = pick(r, []string{"verify", "close", "plan"})
	p.Verify.NightlyFull = ptr(r.Intn(2) == 0)
	if r.Intn(2) == 0 {
		p.Risk.HardFloors[0].Value = r.Intn(3)
	}
	s := p.Risk.Axes[core.AxisScope]
	s.Bands = []int{r.Intn(3), 3 + r.Intn(5)}
	p.Risk.Axes[core.AxisScope] = s
	return p
}

func maybe(r *rand.Rand, p core.Policy) *core.Layer {
	if r.Intn(4) == 0 {
		return nil
	}
	return &core.Layer{Policy: p, Raw: []byte{byte(r.Intn(256))}}
}

func TestResolveNeverLooserThanAnyLayer(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	s := resolver()
	ctx := context.Background()
	for i := range 400 {
		layers := core.PolicyLayers{
			Enterprise: maybe(r, randPolicy(r)), User: maybe(r, randPolicy(r)),
			DefaultBranch: maybe(r, randPolicy(r)), WorkingTree: maybe(r, randPolicy(r)),
		}
		ep, err := s.Resolve(ctx, layers)
		require.NoError(t, err)

		for name, l := range map[string]*core.Layer{"enterprise": layers.Enterprise, "user": layers.User, "default": layers.DefaultBranch} {
			if l == nil {
				continue
			}
			d, ch, err := Diff(l.Policy, ep.Policy, treeFiles)
			require.NoError(t, err)
			require.False(t, d.Loosens(), "iteration %d: effective looser than %s layer: %v", i, name, ch)
		}
		if layers.WorkingTree != nil {
			d, ch, err := Diff(layers.WorkingTree.Policy, ep.Policy, treeFiles)
			require.NoError(t, err)
			if len(ep.Ignored) == 0 {
				require.False(t, d.Loosens(), "iteration %d: applied working tree but looser: %v", i, ch)
			} else {
				without := layers
				without.WorkingTree = nil
				base, err := s.Resolve(ctx, without)
				require.NoError(t, err)
				require.Equal(t, base.Policy, ep.Policy, "iteration %d: ignored working tree must change nothing", i)
			}
		}
		// idempotent: resolving the result as the only project layer changes nothing
		again, err := s.Resolve(ctx, core.PolicyLayers{DefaultBranch: layer(ep.Policy)})
		require.NoError(t, err)
		require.Equal(t, ep.Policy, again.Policy)
	}
}
