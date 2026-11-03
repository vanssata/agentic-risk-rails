package factory

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

const codexOK = `{"type":"thread.started","thread_id":"t"}
{"type":"turn.started"}
{"type":"item.completed","item":{"type":"agent_message","text":"first"}}
{"type":"item.completed","item":{"type":"agent_message","text":"did it\nSTATUS: DONE"}}
{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":800,"output_tokens":50}}
{"type":"turn.started"}
{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":10}}`

func TestCodexRunnerWithFakeBin(t *testing.T) {
	models := map[core.Tier]string{core.TierBalanced: "gpt-x"}
	tests := []struct {
		name       string
		script     string
		timeout    time.Duration
		wantStatus core.WorkerStatus
		wantTokens int64
		wantUsage  core.Usage
		wantCalls  int
	}{
		{"done", `cat > stdin.txt; echo "$@" > args.txt; echo "$RR_X" > env.txt
printf '%s\n' '` + codexOK + `'`, 0, core.StatusDone, 1160, core.Usage{Runtime: "codex", Model: "gpt-x", Input: 300, Output: 60, CacheRead: 800}, 2},
		{"no status line", `echo '{"type":"item.completed","item":{"type":"agent_message","text":"hi"}}
{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}'`, 0, core.StatusBlocked, 2, core.Usage{Runtime: "codex", Model: "gpt-x", Input: 1, Output: 1}, 1},
		{"turn without usage is unknown", `echo '{"type":"item.completed","item":{"type":"agent_message","text":"STATUS: DONE"}}
{"type":"turn.completed"}'`, 0, core.StatusDone, 0, core.Usage{}, 1},
		{"turn.failed", `echo '{"type":"item.completed","item":{"type":"agent_message","text":"STATUS: DONE"}}
{"type":"turn.failed"}'`, 0, core.StatusBlocked, 0, core.Usage{}, 0},
		{"garbage", `echo nope`, 0, core.StatusBlocked, 0, core.Usage{}, 0},
		{"exit error", `echo '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}'; exit 2`, 0, core.StatusBlocked, 0, core.Usage{}, 0},
		{"timeout", `sleep 30`, 200 * time.Millisecond, core.StatusBlocked, 0, core.Usage{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wt := t.TempDir()
			bin := testutil.FakeBin(t, "codex", tc.script)
			got, err := CodexRunner{Bin: bin, Models: models, Timeout: tc.timeout}.Run(context.Background(),
				core.WorkerSpec{Tier: core.TierBalanced, Brief: "the brief", Worktree: wt, Env: []string{"RR_X=hello"}})
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, got.Status)
			assert.Equal(t, tc.wantTokens, got.Tokens)
			got.Usage.Time = time.Time{}
			assert.Equal(t, tc.wantUsage, got.Usage)
			if tc.name == "done" {
				assert.Equal(t, tc.wantCalls, got.Calls)
				args, _ := os.ReadFile(wt + "/args.txt")
				assert.Equal(t, "exec --json --ephemeral --sandbox workspace-write --model gpt-x -", strings.TrimSpace(string(args)))
				stdin, _ := os.ReadFile(wt + "/stdin.txt")
				assert.Equal(t, "the brief", string(stdin))
				env, _ := os.ReadFile(wt + "/env.txt")
				assert.Equal(t, "hello\n", string(env))
			}
		})
	}
}

func TestCodexRunnerReadOnlyAndNoModel(t *testing.T) {
	wt := t.TempDir()
	bin := testutil.FakeBin(t, "codex", `echo "$@" > args.txt`)
	r := CodexRunner{Bin: bin, Models: map[core.Tier]string{core.TierFast: "m"}}.ReadOnly()
	_, err := r.Run(context.Background(), core.WorkerSpec{Tier: core.TierFast, Worktree: wt})
	require.NoError(t, err)
	args, _ := os.ReadFile(wt + "/args.txt")
	assert.Contains(t, string(args), "--sandbox read-only")
	assert.NotContains(t, string(args), "workspace-write")
	_, err = r.Run(context.Background(), core.WorkerSpec{Tier: core.TierStrong})
	assert.Error(t, err)
}

// RR_CONTRACT=1 only: real codex, temp repo, HOME untouched. RR_CODEX_MODEL is
// the cheapest model of the logged-in account. The read-only runner must not
// create the file it is asked to create.
func TestCodexContract(t *testing.T) {
	if os.Getenv("RR_CONTRACT") != "1" {
		t.Skip("RR_CONTRACT=1 required")
	}
	model := os.Getenv("RR_CODEX_MODEL")
	if model == "" {
		t.Skip("RR_CODEX_MODEL required")
	}
	models := map[core.Tier]string{core.TierFast: model}
	repo := testutil.GitRepo(t, map[string]string{"README.md": "x\n"})
	got, err := CodexRunner{Models: models}.Run(context.Background(), core.WorkerSpec{Tier: core.TierFast, Worktree: repo, Brief: "Reply with the single line: STATUS: DONE"})
	require.NoError(t, err)
	assert.Equal(t, core.StatusDone, got.Status, got.Body)
	assert.NotEmpty(t, got.Usage.Model)
	assert.Positive(t, got.Usage.Output)

	ro := testutil.GitRepo(t, map[string]string{"README.md": "x\n"})
	_, err = CodexRunner{Models: models}.ReadOnly().Run(context.Background(), core.WorkerSpec{Tier: core.TierFast, Worktree: ro,
		Brief: "Create a file named created.txt containing hi using a shell command, then end with the line: STATUS: DONE"})
	require.NoError(t, err)
	assert.NoFileExists(t, ro+"/created.txt")
}
