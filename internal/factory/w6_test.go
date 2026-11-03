package factory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// every worker of a step carries the step id (implementer, fixer, both reviewers).
func TestWorkersCarryStep(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{} // role -> step
	impl := runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
		mu.Lock()
		got[s.Role] = s.Step
		mu.Unlock()
		_ = os.WriteFile(filepath.Join(s.Worktree, "a.txt"), []byte(s.Role), 0o644)
		return rep(core.StatusDone, "ok")
	})
	rv := reviews(fail1, pass1, pass1, pass1)
	f, _ := newFactory(t, impl, rv)
	_, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a")}})
	require.NoError(t, err)
	for _, role := range []string{"implementer", "fixer"} {
		assert.Equal(t, "a", got[role], role)
	}
	require.NotEmpty(t, rv.Specs)
	for _, s := range rv.Specs {
		assert.Equal(t, "a", s.Step, s.Role)
	}
}

// Codex workspace-write cannot write under HOME: its Go build cache goes to the temp dir
// (errata #65), unless the caller set GOCACHE itself.
func TestCodexRunnerGoCache(t *testing.T) {
	models := map[core.Tier]string{core.TierFast: "m"}
	run := func(env ...string) string {
		wt := t.TempDir()
		bin := testutil.FakeBin(t, "codex", `echo "$GOCACHE" > gocache.txt`)
		_, err := CodexRunner{Bin: bin, Models: models}.Run(context.Background(), core.WorkerSpec{Tier: core.TierFast, Worktree: wt, Env: env})
		require.NoError(t, err)
		b, _ := os.ReadFile(wt + "/gocache.txt")
		return strings.TrimSpace(string(b))
	}
	assert.True(t, strings.HasPrefix(run(), os.TempDir()+"/rr-gocache-"))
	assert.Equal(t, "/x/cache", run("GOCACHE=/x/cache"))
}

// Read-only Claude workers load only user settings, so the project's Read denies do not
// reach them: DenyRead adds them as --disallowedTools. Zero value = unchanged args.
func TestClaudeReadOnlyDenyRead(t *testing.T) {
	models := map[core.Tier]string{core.TierFast: "haiku"}
	args := func(r ClaudeRunner) string {
		wt := t.TempDir()
		r.Bin, r.Models = testutil.FakeBin(t, "claude", `echo "$@" > args.txt; echo '{"result":"STATUS: DONE"}'`), models
		_, err := r.ReadOnly().Run(context.Background(), core.WorkerSpec{Tier: core.TierFast, Worktree: wt})
		require.NoError(t, err)
		b, _ := os.ReadFile(wt + "/args.txt")
		return strings.TrimSpace(string(b))
	}
	assert.Contains(t, args(ClaudeRunner{}), "--disallowedTools Edit,Write,MultiEdit,NotebookEdit,Bash --setting-sources user")
	got := args(ClaudeRunner{DenyRead: []string{"Read(.env)", "Read(**/secrets/**)"}})
	assert.Contains(t, got, "--disallowedTools Edit,Write,MultiEdit,NotebookEdit,Bash Read(.env) Read(**/secrets/**) --setting-sources user")
	// the implementer (not read-only) is unaffected
	wt := t.TempDir()
	bin := testutil.FakeBin(t, "claude", `echo "$@" > args.txt; echo '{"result":"STATUS: DONE"}'`)
	_, err := ClaudeRunner{Bin: bin, Models: models, DenyRead: []string{"Read(.env)"}}.Run(context.Background(), core.WorkerSpec{Tier: core.TierFast, Worktree: wt})
	require.NoError(t, err)
	b, _ := os.ReadFile(wt + "/args.txt")
	assert.NotContains(t, string(b), "Read(.env)")
}
