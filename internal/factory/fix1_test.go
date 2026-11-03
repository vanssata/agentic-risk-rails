package factory

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
)

func TestRoundTierWithReviewTier(t *testing.T) {
	all := map[core.Tier]bool{core.TierFast: true, core.TierBalanced: true, core.TierStrong: true}
	noStrong := map[core.Tier]bool{core.TierFast: true, core.TierBalanced: true}
	tests := []struct {
		name      string
		tier, rev core.Tier
		eff       map[core.Tier]bool
		round     int
		want      core.Tier
		indep     bool
	}{
		{"empty ReviewTier = Tier, round 1", core.TierBalanced, "", all, 1, core.TierBalanced, false},
		{"empty ReviewTier, round 3 goes up", core.TierBalanced, "", all, 3, core.TierStrong, false},
		{"STRONG review of BALANCED work, round 1", core.TierBalanced, core.TierStrong, all, 1, core.TierStrong, false},
		{"round 2", core.TierBalanced, core.TierStrong, all, 2, core.TierStrong, false},
		{"round 3 above STRONG: independent at STRONG", core.TierBalanced, core.TierStrong, all, 3, core.TierStrong, true},
		{"round 3 up from ReviewTier", core.TierFast, core.TierBalanced, all, 3, core.TierStrong, false},
		{"round 3 up tier missing: independent", core.TierFast, core.TierBalanced, noStrong, 3, core.TierBalanced, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &Factory{Config: Config{Tier: tc.tier, ReviewTier: tc.rev, Effective: tc.eff}}
			got, indep := f.roundTier(tc.round)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.indep, indep)
		})
	}
}

type specRec struct {
	mu    sync.Mutex
	specs []core.WorkerSpec
}

func (r *specRec) Run(_ context.Context, s core.WorkerSpec) (core.WorkerReport, error) {
	r.mu.Lock()
	r.specs = append(r.specs, s)
	r.mu.Unlock()
	if s.Role == "implementer" {
		_ = os.WriteFile(filepath.Join(s.Worktree, "a.txt"), []byte("x\n"), 0o644)
		_ = os.MkdirAll(filepath.Join(s.Worktree, "t"), 0o755)
		_ = os.WriteFile(filepath.Join(s.Worktree, "t", "a_test.txt"), []byte("t\n"), 0o644)
		return rep(core.StatusDone, "ok"), nil
	}
	return rep(core.StatusDone, "fine\nVERDICT: PASS"), nil
}

func TestWorkersGetEnvAndReviewTierAndTestsWritable(t *testing.T) {
	rec := &specRec{}
	f, _ := newFactory(t, rec, rec)
	f.Tier, f.ReviewTier = core.TierBalanced, core.TierStrong
	res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{{ID: "a", Brief: "do a", Files: []string{"a.txt"}, Tests: []string{"t/a_test.txt"}}}})
	require.NoError(t, err)
	require.True(t, res[0].OK(), res[0].Blocked)
	roles := map[string]bool{}
	for _, s := range rec.specs {
		roles[s.Role] = true
		assert.Contains(t, s.Env, "RR_WORKER=1", s.Role)
		if strings.HasPrefix(s.Role, "reviewer") {
			assert.Equal(t, core.TierStrong, s.Tier)
		} else {
			assert.Equal(t, core.TierBalanced, s.Tier)
		}
	}
	assert.True(t, roles["implementer"] && roles["reviewer-spec"] && roles["reviewer-quality"])
	impl := rec.specs[0]
	require.Equal(t, "implementer", impl.Role)
	assert.True(t, slices.ContainsFunc(impl.Env, func(e string) bool { return strings.HasPrefix(e, "RR_SCOPE_FILE=") }))
}

func TestSteersCodex(t *testing.T) {
	for p, want := range map[string]bool{
		".codex/config.toml": true, "sub/.codex/hooks.json": true, ".codex": true,
		"AGENTS.override.md": true, "AGENTS.md": true, "src/a.go": false, ".codexx/a": false,
	} {
		assert.Equal(t, want, steersClaude(p), p)
	}
}
