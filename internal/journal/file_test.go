package journal_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func TestMain(m *testing.M) {
	if root := os.Getenv("RR_JOURNAL_HELPER_ROOT"); root != "" {
		_, err := journal.New(root).Append(context.Background(),
			core.Event{Type: "verify_run", Task: "t1", Actor: core.ActorAgent, Via: os.Getenv("RR_JOURNAL_HELPER_ID")})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var ctx = context.Background()

func ev(typ, task string) core.Event {
	return core.Event{Type: typ, Task: task, Actor: core.ActorAgent}
}

func started(t *testing.T, j core.Journal, task string) {
	t.Helper()
	e := ev("task_started", task)
	e.Data = json.RawMessage(`{"mode":"build"}`)
	_, err := j.Append(ctx, e)
	require.NoError(t, err)
}

func TestAppendFillsAndChains(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	j := journal.NewWithClock(root, func() time.Time { return now })
	a, err := j.Append(ctx, ev("task_started", "t1"))
	require.NoError(t, err)
	assert.Equal(t, 1, a.Schema)
	assert.Equal(t, now, a.Time)
	assert.Equal(t, journal.GenesisPrev, a.PrevSHA256)
	_, err = j.Append(ctx, ev("verify_run", "t1"))
	require.NoError(t, err)
	require.NoError(t, journal.Verify(filepath.Join(root, ".rr/run/t1.jsonl")))
}

func TestRejects(t *testing.T) {
	j := journal.New(t.TempDir())
	_, err := j.Append(ctx, ev("nope_unregistered", "t1"))
	assert.Error(t, err)
	_, err = j.Append(ctx, ev("verify_run", "t1")) // unknown task
	assert.Error(t, err)
	_, err = j.Append(ctx, ev("task_started", "../x"))
	assert.Error(t, err)
}

func TestTaskInFlight(t *testing.T) {
	j := journal.New(t.TempDir())
	started(t, j, "t1")
	_, err := j.Append(ctx, ev("task_started", "t2"))
	var r *core.Refusal
	require.True(t, errors.As(err, &r))
	assert.Equal(t, "TASK_IN_FLIGHT", r.Code)
	open, _ := j.Open(ctx)
	assert.Equal(t, []string{"t1"}, open)
}

func TestTamperDetected(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	started(t, j, "t1")
	for i := 0; i < 4; i++ {
		_, err := j.Append(ctx, ev("verify_run", "t1"))
		require.NoError(t, err)
	}
	p := filepath.Join(root, ".rr/run/t1.jsonl")
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	lines[2] = strings.Replace(lines[2], `"actor":"agent"`, `"actor":"human"`, 1)
	require.NoError(t, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	err := journal.Verify(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 4:") // edit of line 3 breaks the link at line 4
}

func TestUnknownFieldAndNewSchema(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	started(t, j, "t1")
	p := filepath.Join(root, ".rr/run/t1.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"schema":7,"type":"verify_run","task":"t1","future":1,"data":{"x":1}}` + "\n")
	f.Close()
	evs, err := j.Events(ctx, "t1")
	require.NoError(t, err)
	require.Len(t, evs, 2)
	assert.Equal(t, 7, evs[1].Schema)
	assert.JSONEq(t, `{"x":1}`, string(evs[1].Data))
}

func TestCloseMovesFile(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	started(t, j, "t1")
	require.NoError(t, j.Close(ctx, "t1"))
	assert.NoFileExists(t, filepath.Join(root, ".rr/run/t1.jsonl"))
	assert.FileExists(t, filepath.Join(root, ".rr/tasks/t1.jsonl"))
	md, err := os.ReadFile(filepath.Join(root, ".rr/tasks/t1/task.md"))
	require.NoError(t, err)
	assert.Contains(t, string(md), "mode: build")
	evs, err := j.Events(ctx, "t1")
	require.NoError(t, err)
	assert.Len(t, evs, 1)
	_, err = j.Append(ctx, ev("verify_run", "t1"))
	assert.Error(t, err)
	_, err = j.Append(ctx, ev("task_started", "t1"))
	assert.Error(t, err)
	// a new task may start now
	started(t, j, "t2")
}

func TestConcurrentProcesses(t *testing.T) {
	root := t.TempDir()
	started(t, journal.New(root), "t1")
	var wg sync.WaitGroup
	errs := make([]string, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := exec.Command(os.Args[0])
			c.Env = append(os.Environ(), "RR_JOURNAL_HELPER_ROOT="+root, fmt.Sprintf("RR_JOURNAL_HELPER_ID=%d", i))
			if out, err := c.CombinedOutput(); err != nil {
				errs[i] = string(out)
			}
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		require.Empty(t, e)
	}
	p := filepath.Join(root, ".rr/run/t1.jsonl")
	require.NoError(t, journal.Verify(p))
	evs, err := journal.ReadFile(p)
	require.NoError(t, err)
	assert.Len(t, evs, 51) // task_started + 50
}
