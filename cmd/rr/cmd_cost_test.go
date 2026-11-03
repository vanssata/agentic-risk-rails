package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestCostCommand(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	ctx := context.Background()
	// transcripts must live under <root>/.rr (or the home transcript dirs)
	tdir := filepath.Join(root, ".rr", "transcripts")
	require.NoError(t, os.MkdirAll(filepath.Join(tdir, "s1", "subagents"), 0o755))
	for _, f := range []string{"s1.jsonl", "s1/subagents/agent-a.jsonl"} {
		b, err := os.ReadFile(filepath.Join("../../internal/ledger/testdata/claude", f))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(tdir, f), b, 0o644))
	}
	tr := filepath.Join(tdir, "s1.jsonl")
	d, _ := json.Marshal(ledger.SessionData{Runtime: "claude", Session: "s1", Phase: "implement", Path: tr})
	for _, e := range []core.Event{
		{Type: "task_started", Task: "t1", Actor: core.ActorAgent, TiersEffective: map[core.Tier]string{core.TierStrong: "claude-opus-5-5", core.TierBalanced: "claude-sonnet-5-5"}},
		{Type: ledger.EventSession, Task: "t1", Actor: core.ActorAgent, Data: d},
	} {
		e.Schema = 1
		_, err := j.Append(ctx, e)
		require.NoError(t, err)
	}
	out, err := runRR("cost", "--task", "t1", "--root", root)
	require.NoError(t, err)
	assert.Contains(t, out, "$0.0118") // (3200+840+7800)/1e6
	assert.Contains(t, out, "by tier:")
	assert.Contains(t, out, "STRONG")
	assert.Contains(t, out, "in=110 out=70 cache_read=3000 cache_write=200  $0.0040")

	_, err = runRR("cost", "--task", "nope", "--root", root)
	assert.Error(t, err)
	for _, bad := range []string{"../x", "a..b", "a/b", " "} {
		_, err = runRR("cost", "--task", bad, "--root", root)
		assert.ErrorContains(t, err, "invalid --task", bad)
	}
}

func TestCostWorkers(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	w := func(d ledger.WorkerData) core.Event {
		b, _ := json.Marshal(d)
		return core.Event{Type: ledger.EventWorker, Data: b}
	}
	for _, e := range []core.Event{
		{Type: "task_started"},
		w(ledger.WorkerData{Phase: "research", Role: "code-scout", Tier: core.TierFast, Runtime: "claude", Usage: core.Usage{Model: "claude-haiku-5-5", Input: 1000, Output: 100}}),
		w(ledger.WorkerData{Phase: "implement", Role: "implementer", Tier: core.TierBalanced, Runtime: "claude", Usage: core.Usage{Model: "claude-sonnet-5-5", Input: 2000, Output: 500}}),
		w(ledger.WorkerData{Phase: "review", Role: "reviewer-spec", Tier: core.TierStrong, Runtime: "codex", Usage: core.Usage{Model: "gpt-6.1-sol", Input: 500, Output: 50}}),
		w(ledger.WorkerData{Phase: "review", Role: "reviewer-quality", Tier: core.TierStrong, Runtime: "claude", Status: core.StatusDone, Tokens: 9000}),
	} {
		e.Task, e.Actor, e.Schema = "t2", core.ActorAgent, 1
		_, err := j.Append(context.Background(), e)
		require.NoError(t, err)
	}
	out, err := runRR("cost", "--task", "t2", "--root", root)
	require.NoError(t, err)
	testutil.Golden(t, "cost_workers.golden", []byte(out))
}
