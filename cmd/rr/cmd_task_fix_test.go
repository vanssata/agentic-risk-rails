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
	"github.com/vanssata/agentic-risk-rails/internal/flow"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

func startLight(t *testing.T, root string) string {
	t.Helper()
	out, err := runPolicyRR(t, "task", "start", "--root", root, "--goal", "tweak", "--files", light, "--declare", lightDecl)
	require.NoError(t, err, out)
	return openTask(t, root)
}

func TestGuardDeniesAgentRunningTaskClose(t *testing.T) {
	taskRepo(t)
	v := check(context.Background(), core.ToolCall{Tool: "Bash", Command: "env -u CLAUDECODE rr task close"}, "claude")
	assert.Equal(t, core.Deny, v.Decision)
	assert.Contains(t, v.Rule, "AlwaysDeniedCommands")
}

func TestTaskCloseRedVerifyKeepsTaskOpen(t *testing.T) {
	root := taskRepo(t)
	testutil.FakeBin(t, "php", "exit 1") // shadows the green fake
	startLight(t, root)
	_, err := runPolicyRR(t, "task", "close", "--root", root)
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "FACTS", ref.Code)
	assert.Contains(t, ref.Detail, `"green_now":false`)
	assert.Len(t, mustOpen(t, root), 1)
}

func TestTaskCloseRefusesBadTranscript(t *testing.T) {
	root := taskRepo(t)
	task := startLight(t, root)
	outside := filepath.Join(t.TempDir(), "s.jsonl")
	require.NoError(t, os.WriteFile(outside, []byte("{}\n"), 0o644))
	for name, p := range map[string]string{"relative": "s.jsonl", "not jsonl": "/etc/passwd", "outside roots": outside} {
		t.Run(name, func(t *testing.T) {
			_, err := runPolicyRR(t, "task", "close", "--root", root, "--transcript", p)
			require.Error(t, err)
			evs, err := journal.New(root).Events(context.Background(), task)
			require.NoError(t, err)
			for _, e := range evs {
				assert.NotEqual(t, "ledger_session", e.Type)
			}
			assert.Len(t, mustOpen(t, root), 1)
		})
	}
}

func TestTaskHookFailsClosed(t *testing.T) {
	root := taskRepo(t)
	ctx := context.Background()
	tree := []string{light}

	t.Run("two open tasks", func(t *testing.T) {
		r := testutil.GitRepo(t, map[string]string{"a": "x"})
		for _, n := range []string{"a", "b"} {
			require.NoError(t, os.MkdirAll(filepath.Join(r, ".rr/run"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(r, ".rr/run", n+".jsonl"), nil, 0o644))
		}
		_, _, err := flow.TaskHook(ctx, r, tree)
		require.ErrorContains(t, err, "tasks in flight")
	})
	t.Run("task_started without level", func(t *testing.T) {
		r := testutil.GitRepo(t, map[string]string{"a": "x"})
		_, err := journal.New(r).Append(ctx, core.Event{Type: "task_started", Task: "t", Actor: core.ActorHuman, Data: []byte(`{"scope":["a"]}`)})
		require.NoError(t, err)
		_, _, err = flow.TaskHook(ctx, r, tree)
		require.ErrorContains(t, err, "no scope or level")
	})
	t.Run("rewritten scope breaks the chain", func(t *testing.T) {
		startLight(t, root)
		_, err := runPolicyRR(t, "task", "accept", "--root", root)
		require.NoError(t, err)
		_, ok, err := flow.TaskHook(ctx, root, tree)
		require.NoError(t, err)
		require.True(t, ok)
		p := filepath.Join(root, ".rr/run", openTask(t, root)+".jsonl")
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		forged := strings.Replace(string(b), `"scope":["`+light+`"]`, `"scope":["**"]`, 1)
		require.NotEqual(t, string(b), forged)
		require.NoError(t, os.WriteFile(p, []byte(forged), 0o644))
		_, _, err = flow.TaskHook(ctx, root, tree)
		require.Error(t, err)
	})
	t.Run("deleted journal leaves an orphan baseline", func(t *testing.T) {
		r := taskRepo(t)
		task := startLight(t, r)
		require.NoError(t, os.Remove(filepath.Join(r, ".rr/run", task+".jsonl")))
		_, _, err := flow.TaskHook(ctx, r, tree)
		require.ErrorContains(t, err, "baseline without a journal")
	})
	t.Run("a closed task is not an orphan", func(t *testing.T) {
		r := taskRepo(t)
		startLight(t, r)
		_, err := runPolicyRR(t, "task", "close", "--root", r)
		require.NoError(t, err)
		_, ok, err := flow.TaskHook(ctx, r, tree)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

// The runner keeps the journal and the baseline outside the checkout and closes
// through a sandbox (errata #26, #41).
func TestFlowStateRootAndSandbox(t *testing.T) {
	root := taskRepo(t)
	ctx := context.Background()
	state := t.TempDir()
	log := filepath.Join(t.TempDir(), "argv.log")
	testutil.FakeBin(t, "sbx", `echo "$@" >> `+log+`; exit 0`)

	e, r, err := flowEnv(ctx, root)
	require.NoError(t, err)
	e.StateRoot, e.Journal = state, journal.New(state)
	tiers, err := models.FromLock(r.eff.Policy.Models, r.root, "claude")
	require.NoError(t, err)

	s, err := e.Start(ctx, flow.StartIn{ID: "q1", Via: "runner", Goal: "tweak", Files: []string{light}, Declared: map[core.Axis]int{core.AxisBehaviour: 0, core.AxisDomain: 0, core.AxisNovelty: 0}, Tiers: tiers, Actor: core.ActorAutonomy})
	require.NoError(t, err)
	assert.Equal(t, "q1", s.Task)
	assert.NoDirExists(t, filepath.Join(root, ".rr/run"))
	assert.FileExists(t, filepath.Join(state, ".rr/run/q1.baseline.json"))
	evs, err := e.Journal.Events(ctx, "q1")
	require.NoError(t, err)
	assert.Equal(t, "runner", evs[0].Via)

	sb := func(argv []string) ([]string, error) { return append([]string{"sbx"}, argv...), nil }
	require.NoError(t, e.Close(verify.WithSandbox(ctx, sb), flow.CloseIn{Task: "q1", Actor: core.ActorAutonomy}))
	b, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Contains(t, string(b), "phpunit", "the adapter command ran through the sandbox")
	assert.FileExists(t, filepath.Join(state, ".rr/tasks/q1.jsonl"))
	assert.NoDirExists(t, filepath.Join(root, ".rr/tasks"))
}
