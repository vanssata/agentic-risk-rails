package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
	"github.com/vanssata/agentic-risk-rails/internal/research"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

const (
	payFile  = "src/Payment/PaymentService.php"
	goodPlan = "steps:\n  - id: fee\n    brief: add the fee\n    files: [" + payFile + "]\n"
)

const scoutReport = `FACTS:
- OrderService::place calls PaymentGateway::charge synchronously | src/Order/OrderService.php:42 | [V]
- The charge endpoint has a timeout of 30 seconds | src/Payment/Gateway.php:10 | [V]
READ:
- src/Payment/Gateway.php
TOUCHES:
- src/Payment/PaymentService.php
GAPS:
- behaviour of the queue worker under load
COST: tokens=52000 calls=11
`

// scripted answers by role: scouts with a §5.4 report, the implementer edits its
// worktree, reviewers pass. Every report carries Usage.
type scripted struct {
	mu    sync.Mutex
	specs []core.WorkerSpec
}

func (s *scripted) Run(_ context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	s.mu.Lock()
	s.specs = append(s.specs, spec)
	s.mu.Unlock()
	rep := core.WorkerReport{Status: core.StatusDone, Tokens: 1000, Calls: 3,
		Usage: core.Usage{Runtime: "claude", Model: "sonnet", Input: 800, Output: 200}}
	switch {
	case strings.HasSuffix(spec.Role, "-scout"):
		rep.Body = scoutReport
	case strings.HasPrefix(spec.Role, "reviewer"):
		rep.Body = "no findings\nVERDICT: PASS\nSTATUS: DONE"
	default:
		if err := os.WriteFile(filepath.Join(spec.Worktree, payFile), []byte("<?php // fee\n"), 0o644); err != nil {
			return rep, err
		}
		rep.Body = "done\nSTATUS: DONE"
	}
	return rep, nil
}

func (s *scripted) ReadOnly() core.WorkerRunner { return s }

func (s *scripted) roles() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, sp := range s.specs {
		out = append(out, sp.Role)
	}
	return out
}

func fakeWorkers(t *testing.T) *scripted {
	t.Helper()
	s := &scripted{}
	old := runnerFor
	runnerFor = func(string, map[core.Tier]string) (core.WorkerRunner, factory.ReadOnlyRunner, error) { return s, s, nil }
	t.Cleanup(func() { runnerFor = old })
	return s
}

func writePlan(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plan.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func eventTypes(t *testing.T, root, task string) []core.Event {
	t.Helper()
	evs, err := journal.New(root).Events(context.Background(), task)
	require.NoError(t, err)
	return evs
}

func refusal(t *testing.T, err error) *core.Refusal {
	t.Helper()
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	return ref
}

func TestTaskFullFlowResearchAcceptBuildClose(t *testing.T) {
	root := taskRepo(t)
	w := fakeWorkers(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "pay fee", "--files", payFile)
	require.NoError(t, err)
	task := openTask(t, root)

	out, err := runPolicyRR(t, "task", "research", "--root", root)
	require.NoError(t, err, out)
	assert.Equal(t, 5, len(w.roles()), "full: five scouts")
	brief, err := os.ReadFile(filepath.Join(root, ".rr/run", task+".research.md"))
	require.NoError(t, err)
	assert.LessOrEqual(t, research.EstimateTokens(string(brief)), research.MaxBriefTokens)
	assert.Contains(t, string(brief), "PaymentGateway::charge")
	for _, sp := range w.specs {
		assert.Equal(t, root, sp.Worktree, "scouts read the checkout")
	}

	// closing now: a written plan is missing
	_, err = runPolicyRR(t, "task", "close", "--root", root)
	assert.Equal(t, "PLAN_MISSING", refusal(t, err).Code)

	// accept needs a plan above light; a plan outside the scope is refused
	_, err = runPolicyRR(t, "task", "accept", "--root", root)
	require.ErrorContains(t, err, "needs a written plan")
	_, err = runPolicyRR(t, "task", "accept", "--root", root, "--plan",
		writePlan(t, "steps:\n  - id: x\n    files: [src/Security/LoginAuthenticator.php]\n"))
	assert.Equal(t, "PLAN_OUT_OF_SCOPE", refusal(t, err).Code)
	_, err = runPolicyRR(t, "task", "build", "--root", root)
	assert.Equal(t, "PLAN_MISSING", refusal(t, err).Code, "nothing accepted yet")

	out, err = runPolicyRR(t, "task", "accept", "--root", root, "--plan", writePlan(t, goodPlan))
	require.NoError(t, err, out)

	// a plan edited after accept is not built
	statePlan := filepath.Join(root, ".rr/run", task+".plan.yaml")
	require.NoError(t, os.WriteFile(statePlan, []byte(strings.ReplaceAll(goodPlan, "add the fee", "add the fee and more")), 0o600))
	_, err = runPolicyRR(t, "task", "build", "--root", root)
	assert.Equal(t, "PLAN_TAMPERED", refusal(t, err).Code)
	require.NoError(t, os.WriteFile(statePlan, []byte(goodPlan), 0o600))

	out, err = runPolicyRR(t, "task", "build", "--root", root)
	require.NoError(t, err, out)
	assert.Contains(t, out, "factory PASS")
	b, err := os.ReadFile(filepath.Join(root, payFile))
	require.NoError(t, err)
	assert.Equal(t, "<?php // fee\n", string(b), "the step is integrated into the checkout")

	phases := map[string]int{}
	var verdict map[string]any
	for _, ev := range eventTypes(t, root, task) {
		switch ev.Type {
		case ledger.EventWorker:
			var d ledger.WorkerData
			require.NoError(t, json.Unmarshal(ev.Data, &d))
			phases[d.Phase]++
			assert.Equal(t, "claude", d.Runtime)
			assert.Equal(t, "sonnet", d.Usage.Model)
		case "review_verdict":
			var d map[string]any
			require.NoError(t, json.Unmarshal(ev.Data, &d))
			if d["stage"] == "factory" {
				verdict = d
			}
		}
	}
	assert.Equal(t, map[string]int{"research": 5, "implement": 1, "review": 2}, phases)
	require.NotNil(t, verdict)
	assert.Equal(t, "PASS", verdict["verdict"])

	out, err = runPolicyRR(t, "task", "close", "--root", root)
	require.NoError(t, err, out)
	assert.Empty(t, mustOpen(t, root))
}

func TestTaskFlowStepsRefuseAnAgentShell(t *testing.T) {
	root := taskRepo(t)
	fakeWorkers(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "pay fee", "--files", payFile)
	require.NoError(t, err)
	t.Setenv("CLAUDECODE", "1")
	for _, args := range [][]string{{"research"}, {"accept", "--plan", writePlan(t, goodPlan)}, {"build"}} {
		_, err := runPolicyRR(t, append([]string{"task", "--root", root}, args...)...)
		require.ErrorContains(t, err, "CLAUDECODE", args)
	}
	for _, ev := range eventTypes(t, root, openTask(t, root)) {
		assert.NotContains(t, []string{"plan_accepted", "worker_usage"}, ev.Type)
	}
}

func TestTaskResearchLightHasNoScouts(t *testing.T) {
	root := taskRepo(t)
	w := fakeWorkers(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "tweak", "--files", light, "--declare", lightDecl)
	require.NoError(t, err)
	out, err := runPolicyRR(t, "task", "research", "--root", root)
	require.NoError(t, err, out)
	assert.Empty(t, w.roles())
	assert.Contains(t, out, "no research")
}

func TestTaskBuildRuntimeNotInProject(t *testing.T) {
	root := taskRepo(t)
	fakeWorkers(t)
	b, err := os.ReadFile(filepath.Join(root, "riskrails.yaml"))
	require.NoError(t, err)
	body := strings.Replace(string(b), "  # runtimes: [claude, codex]", "  runtimes: [claude]", 1)
	require.NotEqual(t, string(b), body)
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), []byte(body), 0o644))
	testutil.Git(t, root, "add", "-A")
	testutil.Git(t, root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "runtimes")
	_, err = runPolicyRR(t, "task", "start", "--root", root, "--goal", "pay fee", "--files", payFile)
	require.NoError(t, err)
	for _, cmd := range []string{"research", "build"} {
		_, err = runPolicyRR(t, "task", cmd, "--root", root, "--runtime", "codex")
		require.ErrorContains(t, err, "not in project.runtimes", cmd)
	}
}
