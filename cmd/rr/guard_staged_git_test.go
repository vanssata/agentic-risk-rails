package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
	"github.com/vanssata/agentic-risk-rails/templates/precommit"
)

func TestGuardStagedNestedRepoUsesCwdIndex(t *testing.T) {
	dir := stagedRepo(t)
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	testutil.Git(t, sub, "init", "-q", "-b", "main")
	write(t, sub, ".env", "KEY=1\n")
	testutil.Git(t, sub, "add", "-f", ".env")
	t.Chdir(sub)
	_, err := runGuard(t, "", "--staged")
	assert.Equal(t, 2, exitCode(err), "the nested repo's staged secret must be judged")
}

func TestGuardStagedGitlinkAndSymlink(t *testing.T) {
	dir := stagedRepo(t)
	testutil.Git(t, dir, "update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,vendor/mod")
	_, err := runGuard(t, "", "--staged")
	assert.Equal(t, 0, exitCode(err), "a gitlink is judged by path only (no git show)")

	require.NoError(t, os.Symlink("a.txt", filepath.Join(dir, "link")))
	testutil.Git(t, dir, "add", "link")
	_, err = runGuard(t, "", "--staged")
	assert.Equal(t, 0, exitCode(err), "a symlink is judged by its staged target text")

	testutil.Git(t, dir, "update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,.github/workflows/x")
	_, err = runGuard(t, "", "--staged")
	assert.Equal(t, 2, exitCode(err), "a protected gitlink path is denied")
}

// A real `git commit -a` runs the hook with GIT_INDEX_FILE pointing at a
// temporary index; the hook must judge that one.
func TestPreCommitHookCommitAll(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "rr")
	build := exec.Command("go", "build", "-o", bin, "./cmd/rr")
	build.Dir = testutil.RepoRoot(t)
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	t.Setenv("CLAUDE_PROJECT_DIR", "")
	dir := testutil.GitRepo(t, map[string]string{".env.example": "A=1\n"})
	write(t, dir, ".githooks/pre-commit", string(precommit.Script))
	require.NoError(t, os.Chmod(filepath.Join(dir, ".githooks/pre-commit"), 0o755))
	testutil.Git(t, dir, "config", "core.hooksPath", ".githooks")
	write(t, dir, ".env.example", "A=2\n")

	commit := func(args ...string) error {
		c := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x"}, args...)...)
		c.Dir = dir
		c.Env = append(os.Environ(), "PATH="+filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
		return c.Run()
	}
	assert.Error(t, commit("-a"), "commit -a must be denied")
	assert.Error(t, commit("--", ".env.example"), "commit -- <path> must be denied")
	assert.NoError(t, commit("-a", "--no-verify"), "--no-verify is the documented bypass")
}
