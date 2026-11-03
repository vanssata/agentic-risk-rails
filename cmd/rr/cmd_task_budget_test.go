package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// planWorker answers the planner role with a plan; every other role goes to the scripted fake.
type planWorker struct{ *scripted }

func (p planWorker) Run(ctx context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	rep, err := p.scripted.Run(ctx, spec)
	if spec.Role == "planner" {
		rep.Body = "```yaml\n" + goodPlan + "```\nSTATUS: DONE"
	}
	return rep, err
}

func (p planWorker) ReadOnly() core.WorkerRunner { return p }

func TestTaskBuildPreflightRefusal(t *testing.T) {
	root := taskRepo(t)
	w := fakeWorkers(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "pay fee", "--files", payFile)
	require.NoError(t, err)
	_, err = runPolicyRR(t, "task", "accept", "--root", root, "--plan", writePlan(t, goodPlan))
	require.NoError(t, err)

	var got factory.PreflightIn
	noPreflight(t) // restores the real var afterwards
	t.Setenv("CLAUDE_CONFIG_DIR", "/cfg/claude")
	preflightFor = func(_ context.Context, r resolved, runtime string) error {
		got = factory.PreflightIn{Runtime: runtime, Root: r.root, ConfigDir: os.Getenv("CLAUDE_CONFIG_DIR")}
		return &core.Refusal{Code: "REPO_UNTRUSTED", Detail: "trust the repo"}
	}
	_, err = runPolicyRR(t, "task", "build", "--root", root)
	assert.Equal(t, "REPO_UNTRUSTED", refusal(t, err).Code)
	assert.Empty(t, w.roles(), "no worker started")
	assert.Equal(t, "claude", got.Runtime)
	assert.Equal(t, "/cfg/claude", got.ConfigDir)
}

func TestTaskBuildBudgetRefusesBeforeNextWorker(t *testing.T) {
	root := taskRepo(t)
	b, err := os.ReadFile(filepath.Join(root, "riskrails.yaml"))
	require.NoError(t, err)
	body := strings.Replace(string(b), "    full: 3M", "    full: 8000", 1)
	require.NotEqual(t, string(b), body)
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), []byte(body), 0o644))
	testutil.Git(t, root, "add", "-A")
	testutil.Git(t, root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "budget")

	w := &scripted{} // 1000 tokens per run
	pw := planWorker{w}
	old := runnerFor
	runnerFor = func(string, map[core.Tier]string) (core.WorkerRunner, factory.ReadOnlyRunner, error) {
		return pw, pw, nil
	}
	t.Cleanup(func() { runnerFor = old })
	noPreflight(t)

	_, err = runPolicyRR(t, "task", "start", "--root", root, "--goal", "pay fee", "--files", payFile)
	require.NoError(t, err)
	task := openTask(t, root)
	_, err = runPolicyRR(t, "task", "research", "--root", root) // 5 scouts: 5000
	require.NoError(t, err)

	e, _, err := flowEnv(context.Background(), root)
	require.NoError(t, err)
	planFile, err := e.Plan(context.Background(), task, pw, "claude") // 6000
	require.NoError(t, err)
	_, err = runPolicyRR(t, "task", "accept", "--root", root, "--plan", planFile)
	require.NoError(t, err)

	before := len(w.roles())
	out, err := runPolicyRR(t, "task", "build", "--root", root) // implementer 7000, reviewer-spec 8000, then BUDGET
	assert.Equal(t, "BUDGET", refusal(t, err).Code, out)
	assert.Equal(t, 2, len(w.roles())-before, "the third worker never started")
	var exceeded int
	for _, ev := range eventTypes(t, root, task) {
		if ev.Type == "budget_exceeded" {
			exceeded++
		}
	}
	assert.Equal(t, 1, exceeded)

	cost, err := runPolicyRR(t, "cost", "--root", root, "--task", task)
	require.NoError(t, err)
	phase, _, _ := strings.Cut(cost, "by tier")
	for _, p := range []string{"research", "plan", "implement", "review"} {
		assert.Contains(t, phase, p)
	}

	// without a human raising the budget the next build is refused again
	_, err = runPolicyRR(t, "task", "build", "--root", root)
	assert.Equal(t, "BUDGET", refusal(t, err).Code)
	assert.Equal(t, 2, len(w.roles())-before)
}
