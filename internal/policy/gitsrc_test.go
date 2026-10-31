package policy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestInForceLocalBranchWhenNoRemote(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "autonomy: {ceiling: L1}\n", "src/a.php": ""})
	// working tree edit must not matter
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), []byte("autonomy: {ceiling: L4}\n"), 0o644))

	l, err := InForce(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, core.L1, *l.Policy.Autonomy.Ceiling)
	assert.Equal(t, "git:main:riskrails.yaml", l.Source)
	assert.Equal(t, "autonomy: {ceiling: L1}\n", string(l.Raw))
}

func TestInForcePrefersRemoteRef(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "autonomy: {ceiling: L4}\n"})
	run(t, root, "update-ref", "refs/remotes/origin/main", "HEAD") // origin/main = the L4 commit
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), []byte("autonomy: {ceiling: L1}\n"), 0o644))
	run(t, root, "commit", "-qam", "tighten locally")

	l, err := InForce(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, core.L4, *l.Policy.Autonomy.Ceiling, "origin/main wins over a local commit")
	assert.Equal(t, "git:origin/main:riskrails.yaml", l.Source)
}

func TestInForceFollowsOriginHEAD(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "autonomy: {ceiling: L2}\n"})
	run(t, root, "update-ref", "refs/remotes/origin/trunk", "HEAD")
	run(t, root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
	l, err := InForce(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, "git:origin/trunk:riskrails.yaml", l.Source)
}

func TestInForceAbsentFileIsStrictDefaults(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"README.md": "x"})
	l, err := InForce(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, core.StrictDefaults(), l.Policy)
	assert.Contains(t, l.Source, "absent")
}

func TestInForceNoDefaultBranchIsStrictDefaults(t *testing.T) {
	root := t.TempDir()
	run(t, root, "init", "-q", "-b", "feature")
	l, err := InForce(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, core.StrictDefaults(), l.Policy)
}

func TestInForceInvalidPolicyIsAnError(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "bogus: 1\n"})
	_, err := InForce(context.Background(), root)
	assert.Error(t, err)
}

func TestForgedTagCannotShadowRemoteRef(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "autonomy: {ceiling: L1}\n"})
	run(t, root, "update-ref", "refs/remotes/origin/main", "HEAD")
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), []byte("autonomy: {ceiling: L4}\n"), 0o644))
	run(t, root, "commit", "-qam", "loosen")
	run(t, root, "tag", "origin/main", "HEAD") // forged: points at the loosened commit

	l, err := InForce(context.Background(), root)
	require.NoError(t, err)
	assert.Equal(t, core.L1, *l.Policy.Autonomy.Ceiling, "InForce uses fully qualified refs")

	_, err = ReadAtRef(context.Background(), root, "origin/main")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous")
	l, err = ReadAtRef(context.Background(), root, "refs/remotes/origin/main")
	require.NoError(t, err)
	assert.Equal(t, core.L1, *l.Policy.Autonomy.Ceiling)
}

func TestListFilesAtIgnoresTheIndex(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"secrets/a": "", "secrets/b": ""})
	run(t, root, "rm", "-q", "--cached", "secrets/b")
	idx, err := ListFiles(context.Background(), root)
	require.NoError(t, err)
	assert.Contains(t, idx, "secrets/b", "untracked-but-present files are listed")
	require.NoError(t, os.Remove(filepath.Join(root, "secrets", "b")))
	idx, err = ListFiles(context.Background(), root)
	require.NoError(t, err)
	assert.NotContains(t, idx, "secrets/b")
	at, err := ListFilesAt(context.Background(), root, "main")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"secrets/a", "secrets/b"}, at)
}

func TestReadAtRefRejectsBadRefs(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"a": "x"})
	for _, ref := range []string{"", "--output=x", "nope"} {
		_, err := ReadAtRef(context.Background(), root, ref)
		assert.Error(t, err, ref)
	}
}

func TestListFiles(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"a/b.php": "", "c": ""})
	files, err := ListFiles(context.Background(), root)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a/b.php", "c"}, files)
}

func TestCeilingPathsOverrideAndLoad(t *testing.T) {
	ent, usr := CeilingPaths()
	assert.Equal(t, "/etc/riskrails/ceiling.yaml", ent)
	assert.Contains(t, usr, filepath.Join(".config", "riskrails", "ceiling.yaml"))

	dir := t.TempDir()
	restore := SetCeilingPaths(filepath.Join(dir, "e.yaml"), filepath.Join(dir, "u.yaml"))
	defer restore()
	e, u, err := LoadCeilings()
	require.NoError(t, err)
	assert.Nil(t, e)
	assert.Nil(t, u)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "e.yaml"), []byte("remote: o/r\n"), 0o644))
	e, _, err = LoadCeilings()
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "o/r", e.Policy.Remote)
	assert.Equal(t, "remote: o/r\n", string(e.Raw))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "u.yaml"), []byte("bogus: 1\n"), 0o644))
	_, _, err = LoadCeilings()
	assert.Error(t, err)

	restore()
	ent2, _ := CeilingPaths()
	assert.Equal(t, "/etc/riskrails/ceiling.yaml", ent2)
}
