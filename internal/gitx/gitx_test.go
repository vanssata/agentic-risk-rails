package gitx

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubcommand(t *testing.T) {
	assert.Equal(t, "status", subcommand([]string{"-C", "/r", "-c", "a=b", "--literal-pathspecs", "status", "-z"}))
	assert.Equal(t, "?", subcommand([]string{"-C", "/r"}))
}

// A poisoned repo config (fsmonitor, hooks) and inherited GIT_* variables
// must not run anything or redirect git.
func TestPoisonedRepoRunsNothing(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "pwned")
	require.NoError(t, exec.Command("git", "init", "-q", dir).Run())
	cfg := "[core]\n\tfsmonitor = touch " + marker + "\n\thooksPath = " + dir + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o644))
	t.Setenv("GIT_DIR", "/nonexistent")
	_, err := Run(context.Background(), "", "-C", dir, "status", "--porcelain")
	require.NoError(t, err)
	assert.NoFileExists(t, marker)
}
