package flow

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
)

const goodYAML = "steps:\n  - {id: a, files: [src/A.php]}\n"

// planEnv is an Env with an open task in the given mode and level, scope src/**.
func planEnv(t *testing.T, mode core.Mode, level core.Level, budget core.TokenCount) (Env, string) {
	t.Helper()
	root := t.TempDir()
	e := Env{Root: root, Journal: journal.New(root), Policy: core.EffectivePolicy{Policy: core.StrictDefaults()}}
	e.Policy.Policy.Models.Budgets = map[core.Mode]core.TokenCount{mode: budget}
	raw, err := json.Marshal(map[string]any{"goal": "g", "scope": []string{"src/**"}, "mode": mode, "level": level,
		"weight": core.Weight{Mode: mode}})
	require.NoError(t, err)
	_, err = e.Journal.Append(context.Background(), core.Event{Schema: 1, Type: "task_started", Task: "t", Actor: core.ActorHuman, Data: raw,
		TiersEffective: map[core.Tier]string{core.TierStrong: "s", core.TierBalanced: "b"}})
	require.NoError(t, err)
	return e, "t"
}

func planner(body string) *fakes.WorkerRunner {
	return &fakes.WorkerRunner{Reports: []core.WorkerReport{{Status: core.StatusDone, Body: body, Tokens: 10, Usage: core.Usage{Model: "m"}}}}
}

func TestPlanWritesDraftOutsideCheckout(t *testing.T) {
	e, task := planEnv(t, core.ModeLight, core.L2, 0) // light: no scouts, no brief needed
	r := planner("thinking\n```yaml\n" + goodYAML + "```\nSTATUS: DONE")
	f, err := e.Plan(context.Background(), task, r, "claude")
	require.NoError(t, err)
	assert.Equal(t, e.DraftPlanPath(task), f)
	got, err := os.ReadFile(f)
	require.NoError(t, err)
	assert.Equal(t, goodYAML, string(got))
	require.Len(t, r.Specs, 1)
	assert.Equal(t, "planner", r.Specs[0].Role)
	assert.Equal(t, core.TierBalanced, r.Specs[0].Tier)
	assert.Equal(t, e.Root, r.Specs[0].Worktree)
	assert.Contains(t, r.Specs[0].Brief, "GOAL: g")
	assert.NotContains(t, eventTypes(t, e, task), "plan_accepted")
	phases := workerPhases(t, e, task)
	assert.Equal(t, []string{"plan"}, phases)
}

func workerPhases(t *testing.T, e Env, task string) []string {
	t.Helper()
	evs, err := e.Journal.Events(context.Background(), task)
	require.NoError(t, err)
	var out []string
	for _, ev := range evs {
		if ev.Type == ledger.EventWorker {
			var d ledger.WorkerData
			require.NoError(t, json.Unmarshal(ev.Data, &d))
			out = append(out, d.Phase)
		}
	}
	return out
}

func TestPlanProtocol(t *testing.T) {
	for name, tc := range map[string]struct{ body, err string }{
		"valid with concerns": {"```yaml\n" + goodYAML + "```\nSTATUS: DONE_WITH_CONCERNS", ""},
		"no yaml block":       {"plan: none\nSTATUS: DONE", "exactly one"},
		"two blocks":          {"```yaml\n" + goodYAML + "```\n```yaml\n" + goodYAML + "```\nSTATUS: DONE", "exactly one"},
		"unclosed block":      {"```yaml\n" + goodYAML + "STATUS: DONE", "exactly one"},
		"blocked":             {"```yaml\n" + goodYAML + "```\nSTATUS: BLOCKED", "BLOCKED"},
		"needs context":       {"STATUS: NEEDS_CONTEXT", "NEEDS_CONTEXT"},
		"no status line":      {"```yaml\n" + goodYAML + "```\n", "STATUS"},
		"status not last":     {"STATUS: DONE\n```yaml\n" + goodYAML + "```\n", "STATUS"},
		"empty":               {"", "STATUS"},
	} {
		t.Run(name, func(t *testing.T) {
			e, task := planEnv(t, core.ModeLight, core.L2, 0)
			f, err := e.Plan(context.Background(), task, planner(tc.body), "claude")
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.err)
			assert.Empty(t, f)
			_, statErr := os.Stat(e.DraftPlanPath(task))
			assert.True(t, os.IsNotExist(statErr), "no draft is left")
		})
	}
}

func TestPlanNeedsBriefWhenScoutsRun(t *testing.T) {
	e, task := planEnv(t, core.ModeGuarded, core.L3, 0)
	r := planner("```yaml\n" + goodYAML + "```\nSTATUS: DONE")
	_, err := e.Plan(context.Background(), task, r, "claude")
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "RESEARCH_MISSING", ref.Code)
	assert.Empty(t, r.Specs, "no worker ran")

	require.NoError(t, os.MkdirAll(e.Root+"/.rr/run", 0o755))
	require.NoError(t, os.WriteFile(e.BriefPath(task), []byte("BRIEF-MARK"), 0o600))
	_, err = e.Plan(context.Background(), task, r, "claude")
	require.NoError(t, err)
	assert.Contains(t, r.Specs[0].Brief, "BRIEF-MARK")
	assert.Equal(t, core.TierBalanced, r.Specs[0].Tier)
}

func TestAcceptAutonomyNeedsLevelCoveringMode(t *testing.T) {
	for name, tc := range map[string]struct {
		mode  core.Mode
		level core.Level
		ok    bool
	}{
		"guarded L3": {core.ModeGuarded, core.L3, true},
		"guarded L4": {core.ModeGuarded, core.L4, true},
		"guarded L2": {core.ModeGuarded, core.L2, false},
		"full L4":    {core.ModeFull, core.L4, true},
		"full L3":    {core.ModeFull, core.L3, false},
		"light L4":   {core.ModeLight, core.L4, false},
		"programme":  {core.ModeProgramme, core.L4, false},
	} {
		t.Run(name, func(t *testing.T) {
			e, task := planEnv(t, tc.mode, tc.level, 0)
			// the computed level follows the policy: raise its ceiling so only the journaled level decides
			l := core.L4
			e.Policy.Policy.Autonomy.Ceiling = &l
			for m := range e.Policy.Policy.Autonomy.ByMode {
				e.Policy.Policy.Autonomy.ByMode[m] = core.L4
			}
			e.Enforcement, e.InContainer = core.EnforcementSandbox, true
			planFile := t.TempDir() + "/p.yaml"
			require.NoError(t, os.WriteFile(planFile, []byte(goodYAML), 0o600))
			err := e.Accept(context.Background(), task, planFile, core.ActorAutonomy)
			if tc.ok {
				require.NoError(t, err)
				evs, _ := e.Journal.Events(context.Background(), task)
				last := evs[len(evs)-1]
				assert.Equal(t, "plan_accepted", last.Type)
				assert.JSONEq(t, `"autonomy"`, string(mustField(t, last.Data, "by")))
				return
			}
			var ref *core.Refusal
			require.ErrorAs(t, err, &ref)
			assert.Equal(t, "AUTONOMY_LEVEL", ref.Code)
			_, statErr := os.Stat(e.PlanPath(task))
			assert.True(t, os.IsNotExist(statErr), "nothing is accepted")
		})
	}
}

func TestAcceptAutonomyUsesTheLowerOfJournaledAndComputedLevel(t *testing.T) {
	e, task := planEnv(t, core.ModeGuarded, core.L3, 0) // journaled L3, but the default ceiling is L0 now
	planFile := t.TempDir() + "/p.yaml"
	require.NoError(t, os.WriteFile(planFile, []byte(goodYAML), 0o600))
	err := e.Accept(context.Background(), task, planFile, core.ActorAutonomy)
	var ref *core.Refusal
	require.ErrorAs(t, err, &ref)
	assert.Equal(t, "AUTONOMY_LEVEL", ref.Code)
	// the human gate is unchanged
	require.NoError(t, e.Accept(context.Background(), task, planFile, core.ActorHuman))
}

func mustField(t *testing.T, raw json.RawMessage, k string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m))
	return m[k]
}

func eventTypes(t *testing.T, e Env, task string) []string {
	t.Helper()
	evs, err := e.Journal.Events(context.Background(), task)
	require.NoError(t, err)
	var out []string
	for _, ev := range evs {
		out = append(out, ev.Type)
	}
	return out
}
