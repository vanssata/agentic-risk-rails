package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestRunGuardedAtL3FullPipeline(t *testing.T) {
	run := runPipelineQueue(t, core.L3, homePlan, homeFile, autonomy.Task{ID: "t1", Brief: "tweak the home page", Files: []string{homeFile}})
	require.NoError(t, run.err)
	require.Len(t, run.out, 1)
	assert.Equal(t, "pr", run.out[0].Status, "%+v", run.out[0])
	assert.Equal(t, core.L3, run.out[0].Level)
	assert.Positive(t, run.workers.count("-scout"))
	if !run.planStubbed {
		assert.Equal(t, 1, run.workers.count("planner"), "a read-only planner worker writes the plan")
	}
	assert.Equal(t, 1, run.workers.count("implementer"))
	assert.Equal(t, 2, run.workers.count("reviewer"), "two review stages")
	assert.Equal(t, []string{"rr/t1"}, run.host.Pushed)
	require.Len(t, run.host.Opened, 1)
	assert.Equal(t, []string{"rr", "rr:L3", "rr:mode:guarded"}, run.host.Labels[0])

	accepted := false
	for _, ev := range eventTypes(t, run.state, "t1") {
		if ev.Type == "plan_accepted" {
			accepted = true
			assert.Contains(t, string(ev.Data), `"by":"autonomy"`)
		}
	}
	assert.True(t, accepted, "plan_accepted {by: autonomy}")
	assert.Equal(t, run.head, strings.TrimSpace(testutil.Git(t, run.root, "rev-parse", "HEAD")), "checkout back at base")
}

func TestRunGuardedAtCeilingL2IsSkipped(t *testing.T) {
	run := runPipelineQueue(t, core.L2, homePlan, homeFile, autonomy.Task{ID: "t1", Brief: "tweak the home page", Files: []string{homeFile}})
	require.NoError(t, run.err)
	require.Len(t, run.out, 1)
	assert.Equal(t, "skipped", run.out[0].Status)
	assert.Equal(t, core.L1, run.out[0].Level)
	assert.Empty(t, run.workers.specs)
	assert.Empty(t, run.host.Opened)
}

func TestRunFullAtL4ReviewsWithStrong(t *testing.T) {
	run := runPipelineQueue(t, core.L4, goodPlan, payFile, autonomy.Task{ID: "t1", Brief: "pay fee", Files: []string{payFile}})
	require.NoError(t, run.err)
	require.Len(t, run.out, 1)
	assert.Equal(t, "pr", run.out[0].Status, "%+v", run.out[0])
	assert.Equal(t, core.L4, run.out[0].Level)
	assert.Equal(t, []string{"rr", "rr:L4", "rr:mode:full"}, run.host.Labels[0])
	assert.Equal(t, 5, run.workers.count("-scout"), "full: five scouts")
	for _, sp := range run.workers.specs {
		if strings.HasPrefix(sp.Role, "reviewer") && factoryFix1Merged {
			assert.Equal(t, core.TierStrong, sp.Tier, sp.Role)
		}
	}
}

func TestRunPlanOutsideScopeIsBlockedWithoutPR(t *testing.T) {
	outside := "steps:\n  - id: x\n    files: [src/Security/LoginAuthenticator.php]\n"
	run := runPipelineQueue(t, core.L3, outside, homeFile, autonomy.Task{ID: "t1", Brief: "tweak the home page", Files: []string{homeFile}})
	require.NoError(t, run.err)
	require.Len(t, run.out, 1)
	assert.Equal(t, "blocked", run.out[0].Status)
	assert.Empty(t, run.host.Opened)
	assert.Empty(t, run.host.Pushed)
	assert.Zero(t, run.workers.count("implementer"), "nothing was built")
	assert.Equal(t, run.head, strings.TrimSpace(testutil.Git(t, run.root, "rev-parse", "HEAD")), "checkout back at base")
}
