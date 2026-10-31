package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func closedTask(t *testing.T, root string) {
	t.Helper()
	ctx := context.Background()
	j := journal.New(root)
	for _, typ := range []string{"task_started", "plan_accepted", "verify_run", "review_verdict", "task_closed"} {
		_, err := j.Append(ctx, core.Event{Type: typ, Task: "t1", Actor: core.ActorAgent})
		require.NoError(t, err)
	}
	require.NoError(t, j.Close(ctx, "t1"))
}

func TestDoctorDetectsLastLineEditAndTruncation(t *testing.T) {
	root := t.TempDir()
	closedTask(t, root)
	_, err := runRR("doctor", "--root", root)
	require.NoError(t, err)

	p := filepath.Join(root, ".rr", "tasks", "t1.jsonl")
	orig, _ := os.ReadFile(p)

	// last-line edit: chain stays valid, anchor catches it
	lines := strings.Split(strings.TrimSpace(string(orig)), "\n")
	edited := strings.Replace(lines[len(lines)-1], `"agent"`, `"human"`, 1)
	lines[len(lines)-1] = edited
	require.NoError(t, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	out, err := runRR("doctor", "--root", root)
	require.Error(t, err)
	assert.Contains(t, out, "head hash")

	// tail truncation
	require.NoError(t, os.WriteFile(p, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600))
	out, err = runRR("doctor", "--root", root)
	require.Error(t, err)
	assert.Contains(t, out, "head hash")
}

func TestRebuildPreservesHead(t *testing.T) {
	root := t.TempDir()
	closedTask(t, root)
	_, err := runRR("rebuild", "--root", root)
	require.NoError(t, err)
	head, err := journal.ReadHead(root, "t1")
	require.NoError(t, err)
	b, _ := os.ReadFile(filepath.Join(root, ".rr", "index.json"))
	assert.Contains(t, string(b), head)
}

func TestDoctorRepair(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	j := journal.New(root)
	_, err := j.Append(ctx, core.Event{Type: "task_started", Task: "t1"})
	require.NoError(t, err)
	p := filepath.Join(root, ".rr", "run", "t1.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"schema":1,"ty`)
	f.Close()
	_, err = runRR("doctor", "--root", root)
	require.Error(t, err)
	out, err := runRR("doctor", "--root", root, "--repair")
	require.NoError(t, err, out)
	_, err = j.Append(ctx, core.Event{Type: "verify_run", Task: "t1"})
	require.NoError(t, err)
}
