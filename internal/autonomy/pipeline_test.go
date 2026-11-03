package autonomy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// pipeEnv is an env at the given ceiling whose Pipeline records its calls; Build
// commits a change on HEAD the way the factory's cherry-pick does.
type pipeEnv struct {
	*env
	calls []string
	host  *bodyHost
}

func newPipeEnv(t *testing.T, ceiling core.Level) *pipeEnv {
	e := newEnv(t)
	e.pol = pol(ceiling)
	e.pol.Autonomy.Unattended.MaxTasksPerDay = nil
	e.r.Level = ceiling
	p := &pipeEnv{env: e}
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		t.Error("the single implementer must not run for guarded/full")
		return core.WorkerReport{}, nil
	}
	p.host = &bodyHost{lockedHost: e.host}
	e.r.Hosting = p.host
	e.r.Pipeline = &Pipeline{
		Research: func(context.Context, string) error { p.calls = append(p.calls, "research"); return nil },
		Plan: func(context.Context, string) (string, error) {
			p.calls = append(p.calls, "plan")
			return "/state/t1.plan.yaml", nil
		},
		Accept: func(_ context.Context, _, f string) error {
			p.calls = append(p.calls, "accept:"+f)
			return nil
		},
		Build: func(context.Context, string) error {
			p.calls = append(p.calls, "build")
			require.NoError(t, os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("built\n"), 0o644))
			testutil.Git(t, e.root, "-c", "user.name=rr", "-c", "user.email=rr@x", "commit", "-qam", "step s1")
			return nil
		},
		Evidence: func(context.Context, string) (Evidence, error) {
			return Evidence{Plan: "steps: [s1]", Brief: "the brief", Verdict: "factory: PASS", Cost: "research 10 tokens"}, nil
		},
	}
	return p
}

func (p *pipeEnv) run(t *testing.T, mode core.Mode) ([]Outcome, error) {
	return p.r.Run(t.Context(), []Task{{ID: "t1", Brief: "change a", Mode: mode, Files: []string{"a.txt"}}})
}

func TestPipelineGuardedAtL3OpensDraftPR(t *testing.T) {
	p := newPipeEnv(t, core.L3)
	out, err := p.run(t, core.ModeGuarded)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "pr", out[0].Status)
	assert.Equal(t, core.L3, out[0].Level)
	assert.Equal(t, []string{"research", "plan", "accept:/state/t1.plan.yaml", "build"}, p.calls)
	assert.Equal(t, []string{"rr/t1"}, p.host.Pushed)
	require.Len(t, p.host.Opened, 1)
	assert.Equal(t, []string{"rr", "rr:L3", "rr:mode:guarded"}, p.host.Labels[0])
	for _, want := range []string{"steps: [s1]", "the brief", "factory: PASS", "research 10 tokens", "change a"} {
		require.Len(t, p.host.bodies, 1)
		assert.Contains(t, p.host.bodies[0], want)
	}
	assert.Equal(t, "built", strings.TrimSpace(testutil.Git(t, p.root, "show", "rr/t1:a.txt")), "the factory's commit is the PR head")
	assert.Equal(t, "2", strings.TrimSpace(testutil.Git(t, p.root, "rev-list", "--count", "rr/t1")), "base + step commit, no extra runner commit")
}

func TestPipelineFullAtL4LabelsRrL4(t *testing.T) {
	p := newPipeEnv(t, core.L4)
	out, err := p.run(t, core.ModeFull)
	require.NoError(t, err)
	assert.Equal(t, core.L4, out[0].Level)
	assert.Equal(t, []string{"rr", "rr:L4", "rr:mode:full"}, p.host.Labels[0])
}

func TestPipelineSkippedWhenCeilingDoesNotCover(t *testing.T) {
	p := newPipeEnv(t, core.L2)
	out, err := p.run(t, core.ModeGuarded)
	require.NoError(t, err)
	assert.Equal(t, "skipped", out[0].Status)
	assert.Equal(t, core.L1, out[0].Level)
	assert.Empty(t, p.calls)
	assert.Empty(t, p.host.Opened)
}

func TestPipelineFailuresBlockWithoutPR(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(p *Pipeline)
		want string
	}{
		"accept refuses (plan out of scope)": {func(p *Pipeline) {
			p.Accept = func(context.Context, string, string) error {
				return &core.Refusal{Code: "PLAN_OUT_OF_SCOPE", Detail: "x"}
			}
		}, "accept"},
		"factory failed": {func(p *Pipeline) {
			p.Build = func(context.Context, string) error { return &core.Refusal{Code: "FACTORY_FAILED", Detail: "s1"} }
		}, "FACTORY_FAILED"},
		"research incomplete": {func(p *Pipeline) { p.Research = func(context.Context, string) error { return errors.New("scout") } }, "research"},
		"no evidence": {func(p *Pipeline) {
			p.Evidence = func(context.Context, string) (Evidence, error) { return Evidence{}, errors.New("x") }
		}, "evidence"},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPipeEnv(t, core.L3)
			tc.set(p.r.Pipeline)
			head := strings.TrimSpace(testutil.Git(t, p.root, "rev-parse", "HEAD"))
			out, err := p.run(t, core.ModeGuarded)
			require.NoError(t, err)
			assert.Equal(t, "blocked", out[0].Status)
			assert.Empty(t, p.host.Opened)
			assert.Empty(t, p.host.Pushed)
			assert.Equal(t, head, strings.TrimSpace(testutil.Git(t, p.root, "rev-parse", "HEAD")), "back at base")
			assert.Equal(t, "a", strings.TrimSpace(string(mustRead(t, filepath.Join(p.root, "a.txt")))))
			assert.Contains(t, strings.Join(p.jr.Types("run1"), " "), "task_blocked")
			_ = tc.want
		})
	}
}

func TestPipelineBudgetRefusalStopsTheRun(t *testing.T) {
	p := newPipeEnv(t, core.L3)
	p.r.Pipeline.Build = func(context.Context, string) error { return &core.Refusal{Code: "BUDGET", Detail: "tokens"} }
	_, err := p.run(t, core.ModeGuarded)
	assert.Equal(t, "BUDGET", p.refusal(t, err).Code)
	assert.Empty(t, p.host.Opened)
	assert.Contains(t, p.jr.Types("run1"), "run_budget_exceeded")
}

func TestPipelineNotWiredBlocks(t *testing.T) {
	p := newPipeEnv(t, core.L3)
	p.r.Pipeline = nil
	out, err := p.run(t, core.ModeGuarded)
	require.NoError(t, err)
	assert.Equal(t, "blocked", out[0].Status)
	assert.Empty(t, p.host.Opened)
}

func TestPipelineWallBudgetCoversTheWholeFlow(t *testing.T) {
	p := newPipeEnv(t, core.L3)
	p.r.WallUnit = time.Millisecond
	p.r.Pipeline.Plan = func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	_, err := p.run(t, core.ModeGuarded)
	assert.Equal(t, "BUDGET", p.refusal(t, err).Code)
	assert.Empty(t, p.host.Opened)
}

func TestPipelineChangeToProtectedPathIsBlocked(t *testing.T) {
	p := newPipeEnv(t, core.L3)
	p.r.Pipeline.Build = func(context.Context, string) error {
		require.NoError(t, os.WriteFile(filepath.Join(p.root, "riskrails.yaml"), []byte("schema: 1\n# x\n"), 0o644))
		testutil.Git(t, p.root, "-c", "user.name=rr", "-c", "user.email=rr@x", "commit", "-qam", "evil")
		return nil
	}
	out, err := p.run(t, core.ModeGuarded)
	require.NoError(t, err)
	assert.Equal(t, "blocked", out[0].Status)
	assert.Empty(t, p.host.Opened)
}
