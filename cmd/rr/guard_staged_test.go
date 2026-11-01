package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func stagedRepo(t *testing.T) string {
	t.Helper()
	t.Setenv("CLAUDE_PROJECT_DIR", "")
	dir, err := filepath.EvalSymlinks(testutil.GitRepo(t, map[string]string{"a.txt": "a\n", "gone.txt": "x\n"}))
	require.NoError(t, err)
	t.Chdir(dir)
	return dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func TestGuardStaged(t *testing.T) {
	for _, c := range []struct {
		name  string
		stage func(t *testing.T, dir string)
		code  int
	}{
		{"clean diff", func(t *testing.T, dir string) {
			write(t, dir, "a.txt", "b\n")
			testutil.Git(t, dir, "add", "a.txt")
		}, 0},
		{"nothing staged", func(*testing.T, string) {}, 0},
		{"protected path", func(t *testing.T, dir string) {
			write(t, dir, ".github/workflows/ci.yml", "on: push\n")
			testutil.Git(t, dir, "add", "-f", ".github")
		}, 2},
		{"secret file", func(t *testing.T, dir string) {
			write(t, dir, ".env", "KEY=1\n")
			testutil.Git(t, dir, "add", "-f", ".env")
		}, 2},
		{"only the index counts", func(t *testing.T, dir string) {
			write(t, dir, ".env", "KEY=1\n")
			testutil.Git(t, dir, "add", "-f", ".env")
			testutil.Git(t, dir, "rm", "-q", "--cached", ".env")
		}, 0},
		{"one denied edit denies the commit", func(t *testing.T, dir string) {
			testutil.Git(t, dir, "rm", "-q", "gone.txt")
			write(t, dir, ".env", "x")
			testutil.Git(t, dir, "add", "-f", ".env")
		}, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := stagedRepo(t)
			c.stage(t, dir)
			_, err := runGuard(t, "", "--staged")
			assert.Equal(t, c.code, exitCode(err))
		})
	}
}

func TestGuardStagedGitErrorFailsClosed(t *testing.T) {
	t.Setenv("CLAUDE_PROJECT_DIR", "")
	t.Chdir(t.TempDir()) // not a git repository
	_, err := runGuard(t, "", "--staged")
	assert.Equal(t, 2, exitCode(err))
}
