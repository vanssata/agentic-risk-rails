package autonomy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// protectedRepo has policy-protected files at the root, nested, under an
// AlwaysProtected dir, and one that is also a secret.
func protectedRepo(t *testing.T) string {
	root := repo(t)
	for p, c := range map[string]string{"go.mod": "module x\n", "sub/go.mod": "module y\n",
		".github/workflows/ci.yml": "on: push\n", ".env.local": "S=1\n", "lib/a.go": "package lib\n"} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(c), 0o600))
	}
	return root
}

// Wave 4.2: the runtimes' own sandboxes (bwrap) cannot start under --cap-drop ALL,
// so the container makes every existing policy-protected path read-only itself
// (errata #42 "the container is the sandbox"), in the agent and the close sandbox.
func TestPolicyProtectedPathsAreReadOnlyInTheContainer(t *testing.T) {
	root := protectedRepo(t)
	d := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t),
		ROPaths: []string{"go.mod", "**/go.mod", ".env*", ".github/workflows/**", "~/.ssh/**"}, NoRead: []string{".env*"}}
	for _, argv := range []func() ([]string, error){
		func() ([]string, error) { return d.argv(root, "n", "none", true, nil) },
		func() ([]string, error) { return d.CommandArgv("true") },
	} {
		args, err := argv()
		require.NoError(t, err)
		j := " " + strings.Join(args, " ") + " "
		assert.Contains(t, j, " type=bind,src="+root+"/go.mod,dst=/work/go.mod,readonly ")
		assert.Contains(t, j, " type=bind,src="+root+"/sub/go.mod,dst=/work/sub/go.mod,readonly ")
		assert.NotContains(t, j, "dst=/work/.github/workflows", "already read-only with .github")
		assert.NotContains(t, j, "dst=/work/lib")
		ro := strings.Index(j, "src="+root+"/.env.local,")
		mask := strings.Index(j, "src=/dev/null,dst=/work/.env.local,readonly")
		require.Positive(t, mask)
		assert.True(t, ro < 0 || ro < mask, "the secret mask is mounted last and wins")
	}
}

func TestCodexRunsWithoutItsOwnSandboxInTheContainer(t *testing.T) {
	c, err := DockerRunner{Runtime: "codex"}.agentCmd("gpt", 0)
	require.NoError(t, err)
	j := strings.Join(c, " ")
	assert.Contains(t, j, "--sandbox danger-full-access")
	assert.NotContains(t, j, "workspace-write")
	assert.NotContains(t, j, "bypass")
}

// TestProtectedPathsContract (RR_CONTRACT=1, RR_AGENT_IMAGE pinned and present):
// in a real container with the runner's flags, writing, replacing or deleting a
// protected file fails, while the rest of the checkout stays writable.
func TestProtectedPathsContract(t *testing.T) {
	if os.Getenv("RR_CONTRACT") != "1" {
		t.Skip("set RR_CONTRACT=1 and RR_AGENT_IMAGE to run against real docker")
	}
	img := os.Getenv("RR_AGENT_IMAGE")
	require.NotEmpty(t, img)
	root := protectedRepo(t)
	d := DockerRunner{Image: img, Root: root, PolicyFile: policyFile(t), ROPaths: []string{"go.mod", "**/go.mod"}}
	run := func(script string) error {
		args, err := d.CommandArgv("sh", "-c", script)
		require.NoError(t, err)
		return exec.CommandContext(t.Context(), "docker", args...).Run()
	}
	assert.Error(t, run("echo x >> go.mod"), "write")
	assert.Error(t, run("echo x > /tmp/m && mv /tmp/m sub/go.mod"), "replace")
	assert.Error(t, run("rm -f go.mod && test ! -e go.mod"), "delete")
	assert.NoError(t, run("echo x >> lib/a.go"), "the rest stays writable")
	b, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	assert.Equal(t, "module x\n", string(b))
}
