package autonomy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// stepWorktree is a worktree of root: its .git is a FILE, like a factory step.
func stepWorktree(t *testing.T, root string) string {
	dir := filepath.Join(t.TempDir(), "s1")
	testutil.Git(t, root, "worktree", "add", "-q", "-b", "step", dir, "HEAD")
	fi, err := os.Lstat(filepath.Join(dir, ".git"))
	require.NoError(t, err)
	require.True(t, fi.Mode().IsRegular())
	return dir
}

func fakeDockerOK(t *testing.T) (log string) {
	log = filepath.Join(t.TempDir(), "args")
	testutil.FakeBin(t, "docker", `echo "$@" >> `+log+`
cat >/dev/null
echo '{"result":"ok\\nSTATUS: DONE","is_error":false,"num_turns":1,"usage":{"input_tokens":1,"output_tokens":1}}'`)
	return log
}

func wtRunner(t *testing.T, root string) DockerRunner {
	return DockerRunner{Image: testImage, Runtime: "claude", Root: root, Network: "rr-int", ProxyURL: "http://p:3128", PolicyFile: policyFile(t),
		Models: map[core.Tier]string{core.TierBalanced: "m"}, NoRead: []string{".env*"}, ROPaths: []string{"go.mod"}}
}

func TestStepWorktreeMountsOnlyTheWorktreeWithGitFileReadOnly(t *testing.T) {
	root := repo(t)
	wt := stepWorktree(t, root)
	scope := filepath.Join(t.TempDir(), "scope.json")
	require.NoError(t, os.WriteFile(scope, []byte(`["a.txt"]`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(wt, ".env"), []byte("S=1"), 0o600))
	log := fakeDockerOK(t)

	rep, err := wtRunner(t, root).Run(t.Context(), core.WorkerSpec{Role: "implementer", Tier: core.TierBalanced, Worktree: wt, Brief: "x",
		Env: []string{"RR_SCOPE_FILE=" + scope, "RR_WORKER=1", "GOCACHE=/tmp/gc"}})
	require.NoError(t, err)
	assert.Equal(t, core.StatusDone, rep.Status)
	b, _ := os.ReadFile(log)
	j := string(b)
	assert.Contains(t, j, "type=bind,src="+wt+",dst=/work ", "the step worktree is the rw mount")
	assert.NotContains(t, j, "src="+root+",", "the integration checkout and its gitdir are not mounted")
	assert.Contains(t, j, "src="+wt+"/.git,dst=/work/.git,readonly", ".git file read-only")
	assert.Contains(t, j, "src=/dev/null,dst=/work/.env,readonly", "no_read relative to the worktree")
	assert.Contains(t, j, "src="+scope+",dst=/run/rr/scope.json,readonly")
	assert.Contains(t, j, "-e RR_SCOPE_FILE=/run/rr/scope.json")
	assert.NotContains(t, j, "RR_SCOPE_FILE="+scope)
	assert.Contains(t, j, "-e RR_WORKER=1")
	assert.Contains(t, j, "-e GOCACHE=/tmp/gc")
}

func TestReadOnlyRunnerMountsWorkReadOnly(t *testing.T) {
	root := repo(t)
	wt := stepWorktree(t, root)
	log := fakeDockerOK(t)
	_, err := wtRunner(t, root).ReadOnly().Run(t.Context(), core.WorkerSpec{Role: "reviewer-spec", Tier: core.TierBalanced, Worktree: wt, Brief: "x"})
	require.NoError(t, err)
	b, _ := os.ReadFile(log)
	assert.Contains(t, string(b), "type=bind,src="+wt+",dst=/work,readonly ")
}

func TestWorktreeRunRefusals(t *testing.T) {
	root := repo(t)
	wt := stepWorktree(t, root)
	d := wtRunner(t, root)
	spec := func(env ...string) core.WorkerSpec {
		return core.WorkerSpec{Tier: core.TierBalanced, Worktree: wt, Brief: "x", Env: env}
	}
	inside := filepath.Join(wt, "scope.json")
	require.NoError(t, os.WriteFile(inside, []byte("[]"), 0o600))
	for name, env := range map[string][]string{
		"scope file inside the worktree": {"RR_SCOPE_FILE=" + inside},
		"scope file path with a comma":   {"RR_SCOPE_FILE=" + filepath.Join(t.TempDir(), "a,b.json")},
		"override of the policy":         {"RR_POLICY_IN_FORCE=/x"},
		"override of HOME":               {"HOME=/work"},
		"credentials":                    {"ANTHROPIC_API_KEY=k"},
		"not KEY=VALUE":                  {"junk"},
	} {
		_, err := d.Run(t.Context(), spec(env...))
		assert.Error(t, err, name)
	}

	require.NoError(t, os.Remove(filepath.Join(wt, ".git")))
	require.NoError(t, os.Symlink(filepath.Join(root, ".git"), filepath.Join(wt, ".git")))
	_, err := d.Run(t.Context(), spec())
	assert.Error(t, err, ".git symlink")

	comma := filepath.Join(t.TempDir(), "a,b")
	require.NoError(t, os.MkdirAll(comma, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(comma, ".git"), []byte("gitdir: x"), 0o644))
	_, err = d.Run(t.Context(), core.WorkerSpec{Tier: core.TierBalanced, Worktree: comma, Brief: "x"})
	assert.ErrorContains(t, err, "comma")
}
