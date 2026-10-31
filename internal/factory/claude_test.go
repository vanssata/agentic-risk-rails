package factory

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestClaudeRunnerWithFakeBin(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		wantStatus core.WorkerStatus
		wantTokens int64
	}{
		{"done", `cat >/dev/null; echo "$@" > args.txt; pwd > cwd.txt
printf '%s\n' '{"result":"made it\nSTATUS: DONE","is_error":false,"num_turns":4,"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100,"server_tool_use":{"x":1}}}'`, core.StatusDone, 115},
		{"concerns", `printf '%s\n' '{"result":"hmm\nSTATUS: DONE_WITH_CONCERNS","num_turns":1}'`, core.StatusDoneWithConcerns, 0},
		{"no status line fails closed", `printf '%s\n' '{"result":"just text","num_turns":1}'`, core.StatusBlocked, 0},
		{"error result", `printf '%s\n' '{"result":"STATUS: DONE","is_error":true}'; exit 1`, core.StatusBlocked, 0},
		{"garbage", `echo nope; exit 3`, core.StatusBlocked, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wt := t.TempDir()
			bin := testutil.FakeBin(t, "claude", tc.script)
			r := ClaudeRunner{Bin: bin, Models: map[core.Tier]string{core.TierBalanced: "sonnet"}}
			got, err := r.Run(context.Background(), core.WorkerSpec{Role: "implementer", Tier: core.TierBalanced, Brief: "hi", Worktree: wt, MaxTurns: 7})
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, got.Status)
			assert.Equal(t, tc.wantTokens, got.Tokens)
			if tc.name == "done" {
				args, _ := os.ReadFile(wt + "/args.txt")
				for _, want := range []string{"-p", "--output-format json", "--model sonnet", "--max-turns 7", "--permission-mode acceptEdits", "--no-session-persistence"} {
					assert.Contains(t, string(args), want)
				}
				cwd, _ := os.ReadFile(wt + "/cwd.txt")
				assert.True(t, strings.HasSuffix(strings.TrimSpace(string(cwd)), strings.TrimSpace(wt[strings.LastIndex(wt, "/")+1:])))
				assert.Equal(t, 4, got.Calls)
			}
		})
	}
	_, err := ClaudeRunner{}.Run(context.Background(), core.WorkerSpec{Tier: core.TierStrong})
	assert.Error(t, err, "no model for tier")
}

// RR_CONTRACT=1 only: pins the [U] JSON result field names against the real binary.
func TestClaudeContract(t *testing.T) {
	if os.Getenv("RR_CONTRACT") != "1" {
		t.Skip("RR_CONTRACT=1 required")
	}
	r := ClaudeRunner{Models: map[core.Tier]string{core.TierFast: "haiku"}, PermissionMode: "plan"}
	got, err := r.Run(context.Background(), core.WorkerSpec{Tier: core.TierFast, Brief: "Reply with the single line: STATUS: DONE", Worktree: t.TempDir(), MaxTurns: 2})
	require.NoError(t, err)
	assert.Equal(t, core.StatusDone, got.Status)
	assert.Positive(t, got.Tokens)
}
