package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

const payFile = "src/Payment/PaymentService.php"

func patchUpdate(rel, from, to string) string {
	return "*** Begin Patch\n*** Update File: " + rel + "\n@@\n-" + from + "\n+" + to + "\n*** End Patch"
}

// 2. A task that triage lifts above light, under Codex: apply_patch hooks, plan and review gates.
func TestGuardedTaskUnderCodex(t *testing.T) {
	p := newProj(t)
	p.mustRR("sync")
	out := p.mustRR("task", "start", "--goal", "change the payment fee", "--files", payFile, "--runtime", "codex")
	assert.NotContains(t, out, "-> light", "money domain lifts the task above light")
	assert.Contains(t, out, "-> full", "domain>=2 hard floor (the fixture's payment path is not 'guarded')")

	_, code := p.codexPatch(patchUpdate(payFile, "<?php", "<?php // fee"))
	assert.Zero(t, code, "single-file patch inside the scope")

	both := patchUpdate(payFile, "<?php", "<?php // fee")
	both = strings.Replace(both, "*** End Patch", "*** Update File: src/Security/LoginAuthenticator.php\n@@\n-<?php\n+<?php // y\n*** End Patch", 1)
	out, code = p.codexPatch(both)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "LoginAuthenticator.php", "multi-file patch denied for the file outside the scope")

	out, code = p.codexPatch(patchUpdate("riskrails.yaml", "schema: 1", "schema: 1\ncustom: x"))
	assert.NotZero(t, code, "a new field in riskrails.yaml is not allowed through: %s", out)

	out, code = p.rr("task", "close")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "PLAN_MISSING")

	p.mustRR("task", "accept", "--plan", p.planFile("steps:\n  - id: fee\n    files: ["+payFile+"]\n"))
	out, code = p.rr("task", "close")
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "REVIEW_MISSING")

	p.mustRR("task", "review", "--verdict", "PASS")
	p.write(payFile, "<?php // fee\n")
	assert.Contains(t, p.mustRR("task", "close"), "closed")
	assert.Contains(t, p.mustRR("doctor"), "ok")
}

// 3. An agent cannot loosen riskrails.yaml through the hook; tightening is recorded.
func TestPolicyLoosenThroughHook(t *testing.T) {
	for name, tc := range map[string]struct{ old, new string }{
		"remove a deny":        {`, "php bin/console doctrine:schema:drop*"]`, `]`},
		"add an allow":         {`"git status", "git diff*"]`, `"git status", "git diff*", "git push --force*"]`},
		"unprotect .env":       {"    - \".env*\"\n", ""},
		"raise autonomy ceil.": {"ceiling: L2", "ceiling: L4"},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProj(t)
			before := p.read("riskrails.yaml")
			require.Equal(t, 1, strings.Count(before, tc.old))
			out, code := p.claudeHook("Edit", map[string]any{"file_path": p.abs("riskrails.yaml"), "old_string": tc.old, "new_string": tc.new})
			assert.Equal(t, 2, code, out)
			assert.Contains(t, out, "LOOSEN")

			// the same change made by a human is visible to the policy commands
			p.write("riskrails.yaml", strings.Replace(before, tc.old, tc.new, 1))
			out = p.mustRR("policy", "diff", "--base", "HEAD")
			assert.Contains(t, out, "LOOSEN")
			out, code = p.rr("policy", "check", "--base", "HEAD")
			assert.Equal(t, 1, code, out)
		})
	}

	t.Run("tightening", func(t *testing.T) {
		p := newProj(t)
		before := p.read("riskrails.yaml")
		old, repl := `deny:  ["git push --force*",`, `deny:  ["curl *", "git push --force*",`
		out, code := p.claudeHook("Edit", map[string]any{"file_path": p.abs("riskrails.yaml"), "old_string": old, "new_string": repl})
		// recorded behaviour: a tightening edit is allowed; the reason says the task becomes full
		assert.Zero(t, code, out)
		assert.Contains(t, out, "policy tightened")
		p.write("riskrails.yaml", strings.Replace(before, old, repl, 1))
		out = p.mustRR("policy", "diff", "--base", "HEAD")
		assert.Contains(t, out, "TIGHTEN")
		assert.NotContains(t, out, "LOOSEN")
		p.mustRR("policy", "check", "--base", "HEAD")
	})
}

// 4. full_irreversible: triage, task level L0, and the runner refuses to run it unattended.
func TestFullIrreversibleIsL0AndNotRun(t *testing.T) {
	p := newProj(t)
	const mig = "migrations/Version20261031000000.php"
	var tr struct {
		Mode         string `json:"mode"`
		Irreversible bool   `json:"irreversible"`
	}
	require.NoError(t, json.Unmarshal([]byte(p.mustRR("triage", "--json", "--files", mig, "--declare", "domain=2")), &tr))
	assert.Equal(t, "full_irreversible", tr.Mode)
	assert.True(t, tr.Irreversible)

	// without a domain declaration the migration is full (hard floor) but not irreversible-both
	var tr2 struct{ Mode string }
	require.NoError(t, json.Unmarshal([]byte(p.mustRR("triage", "--json", "--files", mig)), &tr2))
	assert.Equal(t, "full", tr2.Mode)

	out := p.mustRR("task", "start", "--goal", "drop a column", "--files", mig, "--declare", "domain=2")
	assert.Contains(t, out, "-> full_irreversible, level L0")
	matches, _ := filepath.Glob(filepath.Join(p.root, ".rr/*/*.jsonl"))
	require.Len(t, matches, 1, "the open task's journal")
	evs, err := journal.ReadFile(matches[0])
	require.NoError(t, err)
	var d struct {
		Mode  string `json:"mode"`
		Level string `json:"level"`
	}
	require.NoError(t, json.Unmarshal(evs[0].Data, &d))
	assert.Equal(t, "full_irreversible", d.Mode)
	assert.Contains(t, []string{"L0", "0"}, d.Level)

	// the runner (Go API; `rr run` needs docker and a GitHub remote) skips it at L2
	h := newRunnerHarness(t)
	outs, err := h.run(t,
		autonomy.Task{ID: "mig", Brief: "drop a column", Mode: core.ModeFullIrreversible},
		autonomy.Task{ID: "mig2", Brief: "drop a column", Irreversible: true},
		autonomy.Task{ID: "big", Brief: "refactor", Mode: core.ModeFull})
	require.NoError(t, err)
	require.Len(t, outs, 3)
	for _, o := range outs {
		assert.Equal(t, "skipped", o.Status, o.Task)
		assert.Less(t, o.Level, core.L2, o.Task)
	}
	assert.Equal(t, core.L0, outs[0].Level)
	assert.Equal(t, core.L0, outs[1].Level)
	assert.Zero(t, h.workerCalls, "the agent never ran")
	assert.Empty(t, h.host.Opened)
}

type runnerHarness struct {
	root        string
	state       string
	host        *fakes.Hosting
	workerCalls int
	worker      func(root string) error
}

func newRunnerHarness(t *testing.T) *runnerHarness {
	t.Helper()
	root := testutil.CopyFixture(t, "php-symfony")
	head := strings.TrimSpace(testutil.Git(t, root, "rev-parse", "HEAD"))
	pol, err := os.ReadFile(filepath.Join(root, "riskrails.yaml"))
	require.NoError(t, err)
	return &runnerHarness{root: root, state: t.TempDir(), host: &fakes.Hosting{
		Files:    map[string][]byte{head + ":riskrails.yaml": pol},
		Branches: map[string]string{"main": head},
	}}
}

type workerFn func(context.Context, core.WorkerSpec) (core.WorkerReport, error)

func (f workerFn) Run(ctx context.Context, s core.WorkerSpec) (core.WorkerReport, error) {
	return f(ctx, s)
}

func (h *runnerHarness) run(t *testing.T, tasks ...autonomy.Task) ([]autonomy.Outcome, error) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.root, "riskrails.yaml"))
	require.NoError(t, err)
	pol, err := policy.Load(raw)
	require.NoError(t, err)
	r := &autonomy.Runner{
		Root: h.root, StateDir: h.state, RunID: "run1", DefaultBranch: "main", Level: core.L2, Container: true,
		Runtime: &fakes.Runtime{ID: "claude", Enf: core.EnforcementSandbox}, Hosting: h.host,
		Journal: journal.New(filepath.Join(h.state, "run")), Tasks: journal.New(h.state),
		Gens: []core.Generator{fakes.Generator{ID: "g", Files: []core.File{{Path: ".claude/settings.json", Content: []byte(`{"cmd":"rr guard"}`)}}}},
		Worker: workerFn(func(context.Context, core.WorkerSpec) (core.WorkerReport, error) {
			h.workerCalls++
			if h.worker != nil {
				if err := h.worker(h.root); err != nil {
					return core.WorkerReport{}, err
				}
			}
			return core.WorkerReport{Status: core.StatusDone, Body: "done", Tokens: 100, Calls: 2}, nil
		}),
		Resolve: func(context.Context, []byte) (core.EffectivePolicy, error) {
			return core.EffectivePolicy{Policy: pol, InForce: pol, PolicySHA: "p", CeilingSHA: "c"}, nil
		},
	}
	return r.Run(t.Context(), tasks)
}

// 5. L2 light through the runner's Go API (GAP: `rr run` links the GitHub hosting
// and a docker image; neither can be faked from the CLI).
func TestRunnerL2LightOpensDraftPR(t *testing.T) {
	h := newRunnerHarness(t)
	h.worker = func(root string) error {
		return os.WriteFile(filepath.Join(root, lightFile), []byte("<?php // tweak\n"), 0o644)
	}
	outs, err := h.run(t, autonomy.Task{ID: "t1", Brief: "tweak the home page", Files: []string{lightFile}})
	require.NoError(t, err)
	require.Len(t, outs, 1)
	assert.Equal(t, "pr", outs[0].Status)
	assert.Equal(t, core.L2, outs[0].Level)
	assert.Equal(t, []string{"rr/t1"}, h.host.Pushed)
	require.Len(t, h.host.Opened, 1)

	assert.Equal(t, lightFile+"\n", testutil.Git(t, h.root, "show", "--name-only", "--format=", "rr/t1"))
	assert.Empty(t, testutil.Git(t, h.root, "status", "--porcelain"), "checkout clean afterwards")
	_, err = os.Stat(filepath.Join(h.root, ".rr"))
	assert.True(t, os.IsNotExist(err), "nothing under the checkout's .rr")
	m, _ := filepath.Glob(filepath.Join(h.state, "*", "*"))
	assert.NotEmpty(t, m, "the runner's journal lives in the state dir: %v", m)
}
