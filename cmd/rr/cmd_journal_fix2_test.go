package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoctorOrphansAndIndex(t *testing.T) {
	root := t.TempDir()
	closedTask(t, root)
	_, err := runRR("rebuild", "--root", root)
	require.NoError(t, err)
	_, err = runRR("doctor", "--root", root)
	require.NoError(t, err)

	// delete journal and task.md of the closed task: index.json makes it visible
	require.NoError(t, os.Remove(filepath.Join(root, ".rr/tasks/t1.jsonl")))
	require.NoError(t, os.Remove(filepath.Join(root, ".rr/tasks/t1/task.md")))
	out, err := runRR("doctor", "--root", root)
	require.Error(t, err)
	assert.Contains(t, out, "listed in index.json")

	// task.md without journal
	require.NoError(t, os.WriteFile(filepath.Join(root, ".rr/tasks/t1/task.md"), []byte("x"), 0o600))
	out, _ = runRR("doctor", "--root", root)
	assert.Contains(t, out, "task.md without journal")
}
