package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/guard"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
	"github.com/vanssata/agentic-risk-rails/internal/wiring"
)

const (
	light     = "src/Controller/HomeController.php"
	lightDecl = "behaviour=0,domain=0,novelty=0"
)

// taskRepo is the php-symfony fixture with a locked BALANCED model, a fake
// php-cs-fixer, a fake php on PATH, and an environment that is not an agent's.
func taskRepo(t *testing.T) string {
	t.Helper()
	t.Cleanup(policy.SetCeilingPaths(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "none")))
	t.Setenv("HOME", t.TempDir())
	for _, k := range []string{"CLAUDECODE", "RR_LEVEL", "RR_HALT_SOCK", "RR_POLICY_IN_FORCE", "CLAUDE_PROJECT_DIR"} {
		t.Setenv(k, "")
		require.NoError(t, os.Unsetenv(k))
	}
	testutil.FakeBin(t, "php", "exit 0")
	root := testutil.CopyFixture(t, "php-symfony")
	fixer := filepath.Join(root, "vendor/bin/php-cs-fixer")
	require.NoError(t, os.MkdirAll(filepath.Dir(fixer), 0o755))
	require.NoError(t, os.WriteFile(fixer, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	testutil.Git(t, root, "add", "-A")
	testutil.Git(t, root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "fixer")
	require.NoError(t, models.WriteLock(root, core.EffectiveTiers{Runtime: "claude",
		Models: map[core.Tier]string{core.TierFast: "haiku", core.TierBalanced: "sonnet", core.TierStrong: "opus"}}))
	t.Setenv("CLAUDE_PROJECT_DIR", root) // where `rr guard` finds the policy, whatever its cwd
	return root
}

func openTask(t *testing.T, root string) string {
	t.Helper()
	open, err := journal.New(root).Open(context.Background())
	require.NoError(t, err)
	require.Len(t, open, 1)
	return open[0]
}

func TestTaskLightStartAmendClose(t *testing.T) {
	root := taskRepo(t)
	ctx := context.Background()

	out, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "tweak the home page", "--files", light, "--declare", lightDecl)
	require.NoError(t, err, out)
	assert.Contains(t, out, "-> light")
	task := openTask(t, root)

	// task_started carries every trust input, tiers and the policy hash.
	events, err := journal.New(root).Events(ctx, task)
	require.NoError(t, err)
	st := events[0]
	assert.Equal(t, "task_started", st.Type)
	assert.NotEmpty(t, st.PolicySHA)
	assert.Equal(t, "sonnet", st.TiersEffective[core.TierBalanced])
	var d map[string]any
	require.NoError(t, json.Unmarshal(st.Data, &d))
	assert.Equal(t, []any{light}, d["scope"])
	assert.Equal(t, "light", d["mode"])
	assert.Regexp(t, `^[0-9a-f]{40}$`, d["base_sha"])
	assert.NotEmpty(t, d["baseline"])
	assert.NotEmpty(t, d["weight"])
	assert.FileExists(t, filepath.Join(root, ".rr/run", task+".baseline.json"))

	// a second task in the same checkout is refused
	_, err = runPolicyRR(t, "task", "start", "--root", root, "--goal", "again", "--files", light)
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "TASK_IN_FLIGHT", ref.Code)

	// the hook of a task in flight: scope guard armed, Level of the task
	gc, err := wiring.GuardContext(ctx, root, "claude")
	require.NoError(t, err)
	assert.Equal(t, []string{light}, gc.StepFiles)
	g := guard.New()
	in := filepath.Join(root, light)
	v := g.Check(ctx, core.ToolCall{Tool: "Write", Paths: []string{in}, Content: "<?php // tweak\n"}, gc)
	assert.Equal(t, core.Allow, v.Decision, v.Reason)
	v = g.Check(ctx, core.ToolCall{Tool: "Write", Paths: []string{filepath.Join(root, "src/Controller/Other.php")}, Content: "<?php\n"}, gc)
	assert.Equal(t, core.Deny, v.Decision)
	assert.Equal(t, "scope_guard", v.Rule)

	require.NoError(t, os.WriteFile(in, []byte("<?php // tweak\n"), 0o644))
	out, err = runPolicyRR(t, "task", "amend", "--root", root)
	require.NoError(t, err, out)
	assert.Contains(t, out, "-> light")

	out, err = runPolicyRR(t, "task", "close", "--root", root)
	require.NoError(t, err, out)
	assert.Contains(t, out, "closed")

	// archived, with the journal events the doctor requires, and the facts
	assert.Empty(t, mustOpen(t, root))
	events, err = journal.ReadFile(filepath.Join(root, ".rr/tasks", task+".jsonl"))
	require.NoError(t, err)
	types := map[string]bool{}
	for _, e := range events {
		types[e.Type] = true
	}
	for _, want := range journal.Required() {
		assert.True(t, types[want], want)
	}
	closed := events[len(events)-1]
	assert.Equal(t, "task_closed", closed.Type)
	assert.Contains(t, string(closed.Data), `"green_now":true`)
	assert.Contains(t, string(closed.Data), `"in_scope":true`)
	assert.Contains(t, string(closed.Data), `"cost"`)
	out, err = runPolicyRR(t, "doctor", "--root", root)
	require.NoError(t, err, out)
}

func mustOpen(t *testing.T, root string) []string {
	t.Helper()
	open, err := journal.New(root).Open(context.Background())
	require.NoError(t, err)
	return open
}

func TestTaskStartRefusals(t *testing.T) {
	root := taskRepo(t)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"absolute scope":  {[]string{"--files", "/etc/passwd"}, "repo-relative"},
		"parent scope":    {[]string{"--files", "../x"}, "repo-relative"},
		"bad declaration": {[]string{"--files", light, "--declare", "scope=9"}, "axis=0..2"},
		"no tier":         {[]string{"--files", light, "--runtime", "codex"}, "NO_TIER"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runPolicyRR(t, append([]string{"task", "start", "--root", root}, tc.args...)...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Empty(t, mustOpen(t, root))
		})
	}
}

func TestTaskAmendGrowsModeOnly(t *testing.T) {
	root := taskRepo(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "tweak", "--files", light, "--declare", lightDecl)
	require.NoError(t, err)

	// a change outside the scope, into a hot path, written behind the hook's back
	pay := filepath.Join(root, "src/Payment/PaymentService.php")
	require.NoError(t, os.WriteFile(pay, []byte("<?php // DROP TABLE x\n"), 0o644))
	out, err := runPolicyRR(t, "task", "amend", "--root", root)
	require.NoError(t, err, out)
	assert.True(t, strings.HasSuffix(strings.TrimSpace(out), "-> full"), out)

	task := openTask(t, root)
	events, err := journal.New(root).Events(context.Background(), task)
	require.NoError(t, err)
	assert.Equal(t, "weight_amended", events[len(events)-1].Type)

	// reverting the change never lowers the mode
	testutil.Git(t, root, "checkout", "--", "src/Payment/PaymentService.php")
	out2, err := runPolicyRR(t, "task", "amend", "--root", root)
	require.NoError(t, err, out2)
	assert.True(t, strings.HasSuffix(strings.TrimSpace(out2), "-> full"), out2)

	// close is refused: a heavier mode needs a plan and a review, and the scope was left
	out, err = runPolicyRR(t, "task", "close", "--root", root)
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref, out)
	assert.Equal(t, "PLAN_MISSING", ref.Code)
	assert.NotEmpty(t, mustOpen(t, root))
}

func TestTaskCloseRefusesOutOfScope(t *testing.T) {
	root := taskRepo(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "tweak", "--files", light, "--declare", lightDecl)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "poison.txt"), []byte("x"), 0o644))
	_, err = runPolicyRR(t, "task", "close", "--root", root)
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "FACTS", ref.Code)
	assert.Contains(t, ref.Detail, "poison.txt")
	assert.NotEmpty(t, mustOpen(t, root), "the task stays open")
}

func TestTaskHumanGatesRefuseAnAgentShell(t *testing.T) {
	root := taskRepo(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "tweak", "--files", light, "--declare", lightDecl)
	require.NoError(t, err)
	for _, env := range []string{"CLAUDECODE", "RR_LEVEL"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "1")
			for _, args := range [][]string{{"close"}, {"accept"}, {"review", "--verdict", "PASS"}} {
				_, err := runPolicyRR(t, append([]string{"task", "--root", root}, args...)...)
				require.Error(t, err, args)
				assert.Contains(t, err.Error(), env)
			}
		})
	}
	assert.NotEmpty(t, mustOpen(t, root))
}

func TestTaskGuardedNeedsPlanAndReview(t *testing.T) {
	root := taskRepo(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "pay", "--files", "src/Payment/PaymentService.php")
	require.NoError(t, err)
	task := openTask(t, root)
	events, _ := journal.New(root).Events(context.Background(), task)
	var d struct {
		Mode core.Mode `json:"mode"`
	}
	require.NoError(t, json.Unmarshal(events[0].Data, &d))
	require.Greater(t, d.Mode.Rank(), core.ModeLight.Rank())
	assert.Len(t, events, 1, "no inline plan above light")

	_, err = runPolicyRR(t, "task", "close", "--root", root)
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "PLAN_MISSING", ref.Code)

	_, err = runPolicyRR(t, "task", "accept", "--root", root)
	require.NoError(t, err)
	_, err = runPolicyRR(t, "task", "close", "--root", root)
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "REVIEW_MISSING", ref.Code)

	_, err = runPolicyRR(t, "task", "review", "--root", root, "--verdict", "PASS")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "src/Payment/PaymentService.php"), []byte("<?php // fee\n"), 0o644))
	out, err := runPolicyRR(t, "task", "close", "--root", root)
	require.NoError(t, err, out)
	assert.Empty(t, mustOpen(t, root))
}

func TestHandoffAndRecall(t *testing.T) {
	root := taskRepo(t)
	_, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "tweak the home page", "--files", light, "--declare", lightDecl)
	require.NoError(t, err)
	task := openTask(t, root)
	require.NoError(t, os.WriteFile(filepath.Join(root, light), []byte("<?php // tweak\n"), 0o644))

	out, err := runPolicyRR(t, "handoff", "--root", root)
	require.NoError(t, err, out)
	b, err := os.ReadFile(filepath.Join(root, ".rr/run", task, "handoff.md"))
	require.NoError(t, err)
	assert.Contains(t, string(b), "tweak the home page")
	assert.Contains(t, string(b), light)

	// recall sees the open task, and a closed one after close
	out, err = runPolicyRR(t, "recall", "--root", root, "--files", light)
	require.NoError(t, err, out)
	assert.Contains(t, out, task)
	assert.Contains(t, out, "[open]")
	out, err = runPolicyRR(t, "task", "close", "--root", root)
	require.NoError(t, err, out)
	out, err = runPolicyRR(t, "recall", "--root", root, "--files", light)
	require.NoError(t, err, out)
	assert.Contains(t, out, "[closed]")
	assert.Contains(t, out, "task_closed")
	out, err = runPolicyRR(t, "recall", "--root", root, "--files", "src/Security/LoginAuthenticator.php")
	require.NoError(t, err, out)
	assert.NotContains(t, out, task)

	// the answer fits its budget
	out, err = runPolicyRR(t, "recall", "--root", root, "--files", light, "--budget", "20")
	require.NoError(t, err, out)
	assert.LessOrEqual(t, len(out), 20*4+60)
}
