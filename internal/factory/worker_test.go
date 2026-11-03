package factory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestClaudeRunnerUsageEnvTimeout(t *testing.T) {
	models := map[core.Tier]string{core.TierBalanced: "sonnet"}
	spec := func(wt string) core.WorkerSpec {
		return core.WorkerSpec{Tier: core.TierBalanced, Worktree: wt, Env: []string{"RR_X=hello"}}
	}
	t.Run("usage and env", func(t *testing.T) {
		wt := t.TempDir()
		bin := testutil.FakeBin(t, "claude", `cat >/dev/null; echo "$RR_X" > env.txt
printf '%s\n' '{"result":"STATUS: DONE","num_turns":2,"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100,"cache_creation_input_tokens":7},"modelUsage":{"claude-small":{"inputTokens":1,"outputTokens":1},"claude-big-1":{"inputTokens":10,"outputTokens":5}}}'`)
		got, err := ClaudeRunner{Bin: bin, Models: models}.Run(context.Background(), spec(wt))
		require.NoError(t, err)
		env, _ := os.ReadFile(wt + "/env.txt")
		assert.Equal(t, "hello\n", string(env))
		assert.Equal(t, "claude", got.Usage.Runtime)
		assert.Equal(t, "claude-big-1", got.Usage.Model)
		assert.Equal(t, [4]int64{10, 5, 100, 7}, [4]int64{got.Usage.Input, got.Usage.Output, got.Usage.CacheRead, got.Usage.CacheWrite})
	})
	t.Run("no modelUsage falls back to --model; no usage is unknown", func(t *testing.T) {
		bin := testutil.FakeBin(t, "claude", `printf '%s\n' '{"result":"STATUS: DONE","usage":{"input_tokens":1,"output_tokens":1}}'`)
		got, _ := ClaudeRunner{Bin: bin, Models: models}.Run(context.Background(), spec(t.TempDir()))
		assert.Equal(t, "sonnet", got.Usage.Model)
		bin = testutil.FakeBin(t, "claude", `printf '%s\n' '{"result":"STATUS: DONE"}'`)
		got, _ = ClaudeRunner{Bin: bin, Models: models}.Run(context.Background(), spec(t.TempDir()))
		assert.Equal(t, core.Usage{}, got.Usage)
	})
	t.Run("timeout is BLOCKED", func(t *testing.T) {
		bin := testutil.FakeBin(t, "claude", `sleep 30`)
		start := time.Now()
		got, err := ClaudeRunner{Bin: bin, Models: models, Timeout: 200 * time.Millisecond}.Run(context.Background(), spec(t.TempDir()))
		require.NoError(t, err)
		assert.Equal(t, core.StatusBlocked, got.Status)
		assert.Less(t, time.Since(start), 10*time.Second)
	})
}

func TestWorkerScopeFile(t *testing.T) {
	var got []core.WorkerSpec
	var perm os.FileMode
	var content []byte
	var mu sync.Mutex
	impl := runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, s)
		if s.Role == "implementer" {
			p := strings.TrimPrefix(s.Env[0], "RR_SCOPE_FILE=")
			if fi, err := os.Stat(p); err == nil {
				perm = fi.Mode().Perm()
			}
			content, _ = os.ReadFile(p)
		}
		_ = os.WriteFile(filepath.Join(s.Worktree, "a.txt"), []byte("x\n"), 0o644)
		return rep(core.StatusDone, "ok")
	})
	f, _ := newFactory(t, impl, reviews(pass1, pass1))
	res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{{ID: "a", Brief: "do a", Files: []string{"a.txt"}}}})
	require.NoError(t, err)
	require.True(t, res[0].OK(), res[0].Blocked)
	require.NotEmpty(t, got)
	require.Len(t, got[0].Env, 2)
	p := strings.TrimPrefix(got[0].Env[0], "RR_SCOPE_FILE=")
	assert.True(t, filepath.IsAbs(p))
	assert.Equal(t, os.FileMode(0o400), perm)
	assert.JSONEq(t, `["a.txt"]`, string(content))
	assert.False(t, strings.HasPrefix(p, filepath.Join(f.WorkDir, "a")+string(filepath.Separator)), "outside the worktree")
	assert.NoFileExists(t, p, "removed after the run")
}
