package journal_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func TestTornTailRefusesAppendAndRepairs(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	started(t, j, "t1")
	p := filepath.Join(root, ".rr/run/t1.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"schema":1,"type":"verif`)
	f.Close()
	before, _ := os.ReadFile(p)
	_, err := j.Append(ctx, ev("verify_run", "t1"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "t1.jsonl")
	after, _ := os.ReadFile(p)
	assert.Equal(t, before, after)
	assert.Error(t, journal.Verify(p))

	fixed, err := journal.Repair(p)
	require.NoError(t, err)
	assert.True(t, fixed)
	require.NoError(t, journal.Verify(p))
	_, err = j.Append(ctx, ev("verify_run", "t1"))
	require.NoError(t, err)
}

func TestRepairKeepsValidJSONTail(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	started(t, j, "t1")
	p := filepath.Join(root, ".rr/run/t1.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"schema":1}`)
	f.Close()
	fixed, err := journal.Repair(p)
	require.Error(t, err)
	assert.False(t, fixed)
}

func TestCloseVerifiesFirst(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	started(t, j, "t1")
	for i := 0; i < 2; i++ {
		_, err := j.Append(ctx, ev("verify_run", "t1"))
		require.NoError(t, err)
	}
	p := filepath.Join(root, ".rr/run/t1.jsonl")
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	lines[1] = strings.Replace(lines[1], `"actor":"agent"`, `"actor":"human"`, 1)
	require.NoError(t, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	require.Error(t, j.Close(ctx, "t1"))
	assert.FileExists(t, p)
	assert.NoFileExists(t, filepath.Join(root, ".rr/tasks/t1.jsonl"))
}

func TestCloseRejectsUnregisteredAndForeignTask(t *testing.T) {
	for name, line := range map[string]string{
		"unregistered": `{"schema":1,"type":"bogus","task":"t1"}`,
		"foreign":      `{"schema":1,"type":"verify_run","task":"other"}`,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			j := journal.New(root)
			started(t, j, "t1")
			p := filepath.Join(root, ".rr/run/t1.jsonl")
			b, _ := os.ReadFile(p)
			// hand-forge a correctly chained line
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			prev := journal.HashLine([]byte(lines[len(lines)-1]))
			forged := strings.Replace(line, "}", `,"prev_sha256":"`+prev+`"}`, 1)
			require.NoError(t, os.WriteFile(p, append(b, []byte(forged+"\n")...), 0o600))
			require.NoError(t, journal.Verify(p))
			require.Error(t, j.Close(ctx, "t1"))
			assert.FileExists(t, p)
		})
	}
}

func TestHeadAnchor(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	started(t, j, "t1")
	_, err := j.Append(ctx, ev("verify_run", "t1"))
	require.NoError(t, err)
	require.NoError(t, j.Close(ctx, "t1"))
	closed := filepath.Join(root, ".rr/tasks/t1.jsonl")
	head, err := journal.ReadHead(root, "t1")
	require.NoError(t, err)
	got, err := journal.HeadHash(closed)
	require.NoError(t, err)
	assert.Equal(t, got, head)
	assert.Len(t, head, 64)
}

func TestValidTaskIDs(t *testing.T) {
	j := journal.New(t.TempDir())
	for _, bad := range []string{"", ".x", "a/b", "a b", "x.jsonl", "-a", "é", strings.Repeat("a", 129)} {
		_, err := j.Append(ctx, core.Event{Type: "task_started", Task: bad})
		assert.Error(t, err, bad)
	}
	_, err := j.Append(ctx, core.Event{Type: "task_started", Task: "feat-1.2_x"})
	assert.NoError(t, err)
}
