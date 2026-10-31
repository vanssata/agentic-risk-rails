package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func TestParsers(t *testing.T) {
	tests := []struct {
		runtime, file string
		want          []core.Usage
	}{
		{"claude", "testdata/claude/s1.jsonl", []core.Usage{
			// m1 appears twice (streaming): last record wins, counted once.
			{Runtime: "claude", Session: "s1", Model: "claude-opus-5-5", Input: 100, Output: 50, CacheRead: 1000, CacheWrite: 200},
			{Runtime: "claude", Session: "s1", Model: "claude-opus-5-5", Input: 10, Output: 20, CacheRead: 2000},
		}},
		{"claude", "testdata/claude/s1/subagents/agent-a.jsonl", []core.Usage{
			{Runtime: "claude", Session: "s1", Model: "claude-sonnet-5-5", Input: 1000, Output: 500, CacheRead: 4000, CacheWrite: 100},
		}},
		{"codex", "testdata/codex.jsonl", []core.Usage{
			// input_tokens include cached: 1000-400, 2000-1500.
			{Runtime: "codex", Session: "c1", Model: "gpt-6.1-sol", Input: 600, Output: 100, CacheRead: 400},
			{Runtime: "codex", Session: "c1", Model: "gpt-6.1-sol", Input: 500, Output: 50, CacheRead: 1500},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()
			got, err := Parsers()[tt.runtime].Parse(f)
			require.NoError(t, err)
			require.Len(t, got, len(tt.want))
			for i := range got {
				got[i].Time = tt.want[i].Time // timestamps are not under test here
				assert.Equal(t, tt.want[i], got[i])
			}
		})
	}
}

func TestCollectAndCost(t *testing.T) {
	sess := func(rt, phase, path string) core.Event {
		d, _ := json.Marshal(SessionData{Runtime: rt, Session: "x", Phase: phase, Path: path})
		return core.Event{Type: EventSession, Data: d}
	}
	events := []core.Event{
		{Type: "task_started", TiersEffective: map[core.Tier]string{
			core.TierStrong: "claude-opus-5-5", core.TierBalanced: "claude-sonnet-5-5"}},
		sess("claude", "implement", filepath.Join("testdata", "claude", "s1.jsonl")), // + subagents/agent-a
		sess("codex", "review", filepath.Join("testdata", "codex.jsonl")),
	}
	items, err := Collect(events)
	require.NoError(t, err)
	p, err := DefaultPrices()
	require.NoError(t, err)

	// Hand-computed USD (per MTok prices in prices.json):
	// opus m1: 100*4 + 200*8 + 1000*0.2 + 50*20 = 3200 ; m2: 10*4 + 2000*0.2 + 20*20 = 840
	// sonnet m3: 1000*2 + 100*4 + 4000*0.1 + 500*10 = 7800
	// gpt r1: 600*2 + 400*0.1 + 100*10 = 2240 ; r2: 500*2 + 1500*0.1 + 50*10 = 1650
	rows := func(dim string) map[string]Row {
		m := map[string]Row{}
		for _, r := range Group(items, p, dim) {
			m[r.Key] = r
		}
		return m
	}
	byPhase := rows("phase")
	assert.InDelta(t, (3200+840+7800)/1e6, byPhase["implement"].USD, 1e-12)
	assert.InDelta(t, (2240+1650)/1e6, byPhase["review"].USD, 1e-12)
	assert.EqualValues(t, 110+1000, byPhase["implement"].Input)
	assert.EqualValues(t, 7000, byPhase["implement"].CacheRead)
	assert.EqualValues(t, 300, byPhase["implement"].CacheWrite)

	byTier := rows("tier")
	assert.InDelta(t, 4040/1e6, byTier["STRONG"].USD, 1e-12)
	assert.InDelta(t, 7800/1e6, byTier["BALANCED"].USD, 1e-12)
	assert.InDelta(t, 3890/1e6, byTier["?"].USD, 1e-12) // gpt model is not in tiers_effective

	byModel := rows("model")
	assert.Len(t, byModel, 3)
	assert.EqualValues(t, 110, byModel["claude-opus-5-5"].Input)
	assert.EqualValues(t, 70, byModel["claude-opus-5-5"].Output)
}

func TestUnpricedModel(t *testing.T) {
	p, err := DefaultPrices()
	require.NoError(t, err)
	rows := Group([]Item{{Usage: core.Usage{Model: "mystery", Input: 5}}}, p, "model")
	require.Len(t, rows, 1)
	assert.Equal(t, 1, rows[0].Unpriced)
	assert.Zero(t, rows[0].USD)
}
