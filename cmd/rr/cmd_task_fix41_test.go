package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/flow"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/projection"
)

func taskEvents(t *testing.T, root, task string) []core.Event {
	t.Helper()
	evs, err := journal.New(root).Events(context.Background(), task)
	require.NoError(t, err)
	return evs
}

func levelOf(t *testing.T, e core.Event) string {
	t.Helper()
	var d struct {
		Level string `json:"level"`
	}
	require.NoError(t, json.Unmarshal(e.Data, &d))
	return d.Level
}

func TestStartJournalsMissingTiersAndClampsLevel(t *testing.T) {
	root := taskRepo(t)
	require.NoError(t, models.WriteLock(root, core.EffectiveTiers{Runtime: "claude",
		Models: map[core.Tier]string{core.TierFast: "haiku", core.TierBalanced: "sonnet"}})) // no STRONG
	task := startLight(t, root)
	evs := taskEvents(t, root, task)
	var types []string
	for _, e := range evs {
		types = append(types, e.Type)
	}
	assert.Equal(t, []string{"task_started", "tiers_resolved", "tier_missing", "tier_missing", "autonomy_clamped"}, types)
	assert.Equal(t, "L0", levelOf(t, evs[0]), "hook_only is L1; STRONG missing drops it to L0")
	assert.Equal(t, "L0", levelOf(t, evs[4]))
	h, ok, err := flow.TaskHook(context.Background(), root, []string{light})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, core.L0, h.Level)
}

func TestStartWithAllTiersIsNotClamped(t *testing.T) {
	root := taskRepo(t)
	task := startLight(t, root)
	evs := taskEvents(t, root, task)
	for _, e := range evs {
		assert.NotEqual(t, "autonomy_clamped", e.Type)
	}
	assert.Equal(t, "L1", levelOf(t, evs[0]))
}

func TestStartJournalsPolicyClampAndIgnored(t *testing.T) {
	root := taskRepo(t)
	e, r, err := flowEnv(context.Background(), root)
	require.NoError(t, err)
	e.Policy.Clamped = []string{"autonomy.ceiling"}
	e.Policy.Ignored = []string{"verify.adapters"}
	e.Via = "runner"
	tiers, err := models.FromLock(r.eff.Policy.Models, r.root, "claude")
	require.NoError(t, err)
	s, err := e.Start(context.Background(), flow.StartIn{Goal: "tweak", Files: []string{light},
		Declared: map[core.Axis]int{"behaviour": 0, "domain": 0, "novelty": 0}, Tiers: tiers, Actor: core.ActorHuman})
	require.NoError(t, err)
	got := map[string]core.Event{}
	for _, ev := range taskEvents(t, root, s.Task) {
		got[ev.Type] = ev
		assert.Equal(t, "runner", ev.Via)
	}
	assert.JSONEq(t, `{"fields":["autonomy.ceiling"]}`, string(got["policy_clamped"].Data))
	assert.JSONEq(t, `{"fields":["verify.adapters"]}`, string(got["policy_loosening_ignored"].Data))
}

func TestAmendToIrreversibleLowersLevelAndStatusMode(t *testing.T) {
	root := taskRepo(t)
	task := startLight(t, root)
	out, err := runPolicyRR(t, "task", "amend", "--root", root, "--declare", "reversibility=2,domain=2")
	require.NoError(t, err, out)
	evs := taskEvents(t, root, task)
	last := evs[len(evs)-1]
	require.Equal(t, "weight_amended", last.Type)
	assert.Equal(t, "L0", levelOf(t, last))
	h, _, err := flow.TaskHook(context.Background(), root, []string{light})
	require.NoError(t, err)
	assert.Equal(t, core.L0, h.Level)
	assert.Equal(t, "full_irreversible", projection.Summarize(evs).Mode)
}

func TestTaskRiskRecordsAndIsHumanOnly(t *testing.T) {
	root := taskRepo(t)
	task := startLight(t, root)
	out, err := runPolicyRR(t, "task", "risk", "--root", root, "--severity", "high", "flaky payment retry")
	require.NoError(t, err, out)
	risks := projection.Risks(taskEvents(t, root, task))
	require.Len(t, risks, 1)
	assert.Contains(t, string(risks[0].Data), `"severity":"high"`)
	assert.Contains(t, string(risks[0].Data), "flaky payment retry")

	t.Setenv("CLAUDECODE", "1")
	_, err = runPolicyRR(t, "task", "risk", "--root", root, "x")
	require.ErrorContains(t, err, "CLAUDECODE")
	v := check(context.Background(), core.ToolCall{Tool: "Bash", Command: `rr task risk "x"`}, "claude")
	assert.Equal(t, core.Deny, v.Decision)
}
