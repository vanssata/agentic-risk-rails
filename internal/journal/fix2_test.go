package journal_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func TestModeInjectionCannotForgeAnchor(t *testing.T) {
	root := t.TempDir()
	j := journal.New(root)
	e := ev("task_started", "t1")
	e.Data = json.RawMessage(`{"mode":"light\n- head: ` + string(make([]byte, 0)) + `deadbeef"}`)
	_, err := j.Append(context.Background(), e)
	require.NoError(t, err)
	require.NoError(t, j.Close(context.Background(), "t1"))
	head, err := journal.ReadHead(root, "t1")
	require.NoError(t, err)
	real, err := journal.HeadHash(filepath.Join(root, ".rr/tasks/t1.jsonl"))
	require.NoError(t, err)
	assert.Equal(t, real, head)
}

func TestReadHeadRequiresHex(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, ".rr/tasks/t1")
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "task.md"), []byte("- head: deadbeef\n"), 0o600))
	_, err := journal.ReadHead(root, "t1")
	assert.Error(t, err)
	_ = core.Event{}
}
