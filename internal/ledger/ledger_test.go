package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	td, err := filepath.Abs("testdata")
	require.NoError(t, err)
	sess := sessEvent
	events := []core.Event{
		{Type: "task_started", TiersEffective: map[core.Tier]string{
			core.TierStrong: "claude-opus-5-5", core.TierBalanced: "claude-sonnet-5-5"}},
		sess("claude", "implement", filepath.Join(td, "claude", "s1.jsonl")), // + subagents/agent-a
		sess("codex", "review", filepath.Join(td, "codex.jsonl")),
	}
	items, err := Collect(events, []string{td})
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

func sessEvent(rt, phase, path string) core.Event {
	d, _ := json.Marshal(SessionData{Runtime: rt, Session: "x", Phase: phase, Path: path})
	return core.Event{Type: EventSession, Data: d}
}

func TestCollectRefusesPaths(t *testing.T) {
	td, err := filepath.Abs("testdata")
	require.NoError(t, err)
	for _, p := range []string{
		"", "testdata/codex.jsonl", // not absolute
		td + "/../testdata/codex.jsonl",             // not clean
		"/etc/passwd",                               // outside roots, not jsonl
		"/etc/hosts.jsonl",                          // outside roots
		td + "/codex.json",                          // wrong suffix
		filepath.Dir(td) + "/testdata-evil/x.jsonl", // sibling sharing a prefix
	} {
		_, err := Collect([]core.Event{sessEvent("codex", "x", p)}, []string{td})
		require.Error(t, err, p)
	}
}

func write(t *testing.T, dir, name, body string) string {
	p := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func TestParseLines(t *testing.T) {
	good := `{"type":"assistant","message":{"id":"a","model":"m","usage":{"input_tokens":1}}}` + "\n"
	cx := func(in, cached int) string {
		return fmt.Sprintf(`{"type":"token_usage_record","payload":{"usage":{"input_tokens":%d,"cached_input_tokens":%d}}}`+"\n", in, cached)
	}
	tests := []struct {
		name, runtime, body string
		wantIn              int64
		wantN               int
		wantErr             bool
	}{
		{"unterminated last line skipped", "claude", good + `{"type":"assist`, 1, 1, false},
		{"corrupt middle line errors", "claude", good + "SECRET-CONTENT\n" + good, 0, 0, true},
		{"corrupt terminated last line errors", "claude", good + "SECRET-CONTENT\n", 0, 0, true},
		{"codex input clamped at zero", "codex", cx(100, 300), 0, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			us, err := Parsers()[tt.runtime].Parse(strings.NewReader(tt.body))
			if tt.wantErr {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "SECRET")
				return
			}
			require.NoError(t, err)
			require.Len(t, us, tt.wantN)
			assert.Equal(t, tt.wantIn, us[0].Input)
		})
	}
}

func TestCollectNoDoubleCount(t *testing.T) {
	dir := t.TempDir()
	line := func(id string, out int) string {
		return fmt.Sprintf(`{"type":"assistant","sessionId":"s","message":{"id":"%s","model":"claude-opus-5-5","usage":{"output_tokens":%d}}}`+"\n", id, out)
	}
	a := write(t, dir, "a.jsonl", line("m1", 10)+line("m2", 5))
	// second transcript repeats m1 (e.g. a resumed session replaying history)
	b := write(t, dir, "b.jsonl", line("m1", 10))
	events := []core.Event{
		sessEvent("claude", "plan", a), sessEvent("claude", "plan", a), // same path twice
		sessEvent("claude", "implement", b),
	}
	items, err := Collect(events, []string{dir})
	require.NoError(t, err)
	var out int64
	for _, it := range items {
		out += it.Output
	}
	assert.EqualValues(t, 15, out)
	assert.Len(t, items, 2)
}
