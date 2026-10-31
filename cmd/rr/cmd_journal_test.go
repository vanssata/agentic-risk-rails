package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func runRR(args ...string) (string, error) {
	cmd := cli.Root("test")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestStatusDoctorRebuild(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	j := journal.New(root)

	out, err := runRR("status", "--root", root)
	require.NoError(t, err)
	assert.Contains(t, out, "no open task")

	add := func(typ, data string) {
		e := core.Event{Type: typ, Task: "t1", Actor: core.ActorAgent}
		if data != "" {
			e.Data = json.RawMessage(data)
		}
		_, err := j.Append(ctx, e)
		require.NoError(t, err)
	}
	add("task_started", `{"mode":"build"}`)
	out, err = runRR("status", "--root", root, "--json")
	require.NoError(t, err)
	assert.Contains(t, out, `"mode": "build"`)

	for _, typ := range []string{"plan_accepted", "verify_run", "review_verdict", "task_closed"} {
		add(typ, "")
	}
	require.NoError(t, j.Close(ctx, "t1"))
	out, err = runRR("doctor", "--root", root)
	require.NoError(t, err, out)

	_, err = runRR("rebuild", "--root", root)
	require.NoError(t, err)
	b, err := os.ReadFile(filepath.Join(root, ".rr", "index.json"))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"task": "t1"`)
	assert.FileExists(t, filepath.Join(root, ".rr", "run", "state.cache.json"))

	// problems: missing task.md, then tampered chain
	require.NoError(t, os.Remove(filepath.Join(root, ".rr", "tasks", "t1", "task.md")))
	out, err = runRR("doctor", "--root", root)
	var ee ExitError
	require.True(t, errors.As(err, &ee))
	assert.Contains(t, out, "task.md missing")
}

func TestDoctorMissingRequiredAndTamper(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	j := journal.New(root)
	_, err := j.Append(ctx, core.Event{Type: "task_started", Task: "t1"})
	require.NoError(t, err)
	_, err = j.Append(ctx, core.Event{Type: "refused", Task: "t1"})
	require.NoError(t, err)
	_, err = j.Append(ctx, core.Event{Type: "refused", Task: "t1"})
	require.NoError(t, err)
	require.NoError(t, j.Close(ctx, "t1"))
	out, err := runRR("doctor", "--root", root)
	require.Error(t, err)
	assert.Contains(t, out, "required event verify_run missing")

	p := filepath.Join(root, ".rr", "tasks", "t1.jsonl")
	b, _ := os.ReadFile(p)
	require.NoError(t, os.WriteFile(p, []byte(strings.Replace(string(b), `"type":"refused"`, `"type":"verify_run"`, 1)), 0o644))
	out, _ = runRR("doctor", "--root", root)
	assert.Contains(t, out, "line 3")
}
