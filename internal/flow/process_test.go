package flow

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func TestCheckPlanRefusesProtectedPaths(t *testing.T) {
	var e Env
	e.Policy.Policy.Enforcement.ProtectedPaths = []string{".env*", "config/secrets/**"}
	for _, f := range []string{"riskrails.yaml", ".rr/run/x.plan.yaml", ".claude/settings.json", ".github/workflows/ci.yml",
		".githooks/pre-commit", ".env.local", "config/secrets/a.yaml", "sub/.git/config", "a/.rr/x"} {
		t.Run(f, func(t *testing.T) {
			_, err := checkPlan([]byte("steps:\n  - {id: a, files: ["+f+"]}\n"), []string{"**"}, e.protected())
			require.Error(t, err)
			assert.Regexp(t, "protected path|inside a", err.Error())
		})
	}
	_, err := checkPlan([]byte("steps:\n  - {id: a, files: [src/A.php], tests: [riskrails.yaml]}\n"), []string{"**"}, e.protected())
	require.ErrorContains(t, err, "protected path", "tests are checked too")
	_, err = checkPlan([]byte("steps:\n  - {id: a, files: [src/A.php]}\n"), []string{"**"}, e.protected())
	require.NoError(t, err)
}

func ev(t *testing.T, typ string, data map[string]any) core.Event {
	t.Helper()
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	return core.Event{Type: typ, Task: "t", Data: raw}
}

func TestProcessCountsOnlyGateEvents(t *testing.T) {
	written := ev(t, "plan_accepted", map[string]any{"plan": "written", "sha": "abc"})
	for name, tc := range map[string]struct {
		events []core.Event
		code   string
	}{
		"complete":                     {[]core.Event{written, ev(t, "review_verdict", map[string]any{"stage": "factory", "verdict": "PASS", "plan_sha": "abc"})}, ""},
		"factory PASS of another plan": {[]core.Event{written, ev(t, "review_verdict", map[string]any{"stage": "factory", "verdict": "PASS", "plan_sha": "old"})}, "REVIEW_MISSING"},
		"plan re-accepted after PASS": {[]core.Event{written, ev(t, "review_verdict", map[string]any{"stage": "human", "verdict": "PASS"}),
			ev(t, "plan_accepted", map[string]any{"plan": "written", "sha": "def"})}, "REVIEW_MISSING"},
		"human verdict":              {[]core.Event{written, ev(t, "review_verdict", map[string]any{"stage": "human", "verdict": "PASS"})}, ""},
		"killed after a step PASS":   {[]core.Event{written, ev(t, "review_verdict", map[string]any{"step": "s", "stage": "reviewer-quality", "verdict": "PASS"})}, "REVIEW_MISSING"},
		"factory FAIL after step OK": {[]core.Event{written, ev(t, "review_verdict", map[string]any{"stage": "factory", "verdict": "FAIL"})}, "REVIEW_MISSING"},
		"light accept (no sha)":      {[]core.Event{ev(t, "plan_accepted", map[string]any{"plan": "written"}), ev(t, "review_verdict", map[string]any{"stage": "human", "verdict": "PASS"})}, "PLAN_MISSING"},
		"inline plan":                {[]core.Event{ev(t, "plan_accepted", map[string]any{"plan": "inline"}), ev(t, "review_verdict", map[string]any{"stage": "human", "verdict": "PASS"})}, "PLAN_MISSING"},
	} {
		t.Run(name, func(t *testing.T) {
			e := Env{Journal: journal.New(t.TempDir())}
			_, err := e.process(context.Background(), "t", core.ActorHuman, core.ModeGuarded, tc.events)
			if tc.code == "" {
				require.NoError(t, err)
				return
			}
			var ref *core.Refusal
			require.ErrorAs(t, err, &ref)
			assert.Equal(t, tc.code, ref.Code)
		})
	}
}
