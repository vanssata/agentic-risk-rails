package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (p *proj) planFile(body string) string {
	p.t.Helper()
	f := filepath.Join(p.t.TempDir(), "plan.yaml")
	require.NoError(p.t, os.WriteFile(f, []byte(body), 0o644))
	return f
}

// The happy path with scripted workers (5 scouts, brief, plan, both review stages,
// close, worker_usage phases) runs in-process: cmd/rr TestTaskFullFlowResearchAcceptBuildClose.
// Here: what the real binary refuses on a guarded+ task.
func TestFlowGatesOnAGuardedTask(t *testing.T) {
	p := newProj(t)
	out := p.mustRR("task", "start", "--goal", "pay fee", "--files", payFile)
	assert.NotContains(t, out, "-> light")

	out, code := p.rr("task", "close")
	assert.NotZero(t, code)
	assert.Contains(t, out, "PLAN_MISSING")

	out, code = p.rr("task", "accept")
	assert.NotZero(t, code, "no plan file above light")
	assert.Contains(t, out, "needs a written plan")

	out, code = p.rr("task", "accept", "--plan", p.planFile("steps:\n  - id: x\n    files: [src/Security/LoginAuthenticator.php]\n"))
	assert.NotZero(t, code)
	assert.Contains(t, out, "PLAN_OUT_OF_SCOPE")

	out, code = p.rr("task", "build")
	assert.NotZero(t, code, "nothing accepted: no build")
	assert.Contains(t, out, "PLAN_MISSING")

	// a runtime with no worker runner is refused before anything runs
	out, code = p.rr("task", "research", "--runtime", "gemini")
	assert.NotZero(t, code)
	assert.Contains(t, out, "gemini")
}

func TestFlowStepsAreNotForAnAgentShell(t *testing.T) {
	p := newProj(t)
	p.mustRR("task", "start", "--goal", "pay fee", "--files", payFile)
	plan := p.planFile("steps:\n  - id: fee\n    files: [" + payFile + "]\n")
	p.env = append(p.env, "CLAUDECODE=1")
	for _, args := range [][]string{{"research"}, {"accept", "--plan", plan}, {"build"}} {
		out, code := p.rr(append([]string{"task"}, args...)...)
		assert.NotZero(t, code, args)
		assert.Contains(t, out, "CLAUDECODE", args)
	}
}
