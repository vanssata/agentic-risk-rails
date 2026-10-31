package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
)

func TestCostCommand(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	ctx := context.Background()
	tr, err := filepath.Abs("../../internal/ledger/testdata/claude/s1.jsonl")
	require.NoError(t, err)
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
}
