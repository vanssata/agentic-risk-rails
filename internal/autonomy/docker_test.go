package autonomy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

const testImage = "rr@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func repo(t *testing.T) string {
	return testutil.GitRepo(t, map[string]string{"riskrails.yaml": "schema: 1\n", ".github/w.yml": "x", "a.txt": "a"})
}

func TestDockerArgv(t *testing.T) {
	root := repo(t)
	d := DockerRunner{Image: testImage, Runtime: "claude", Root: root, Sock: "/tmp/h.sock", Level: core.L2}
	args, err := d.argv(root, "n1", "none", true, []string{"claude", "-p"})
	require.NoError(t, err)
	j := " " + strings.Join(args, " ") + " "
	assert.Contains(t, j, " --network none ")
	assert.Contains(t, j, " --cap-drop ALL ")
	for _, p := range []string{"riskrails.yaml", ".git", ".github"} {
		assert.Contains(t, j, "dst="+workDir+"/"+p+",readonly ", p)
	}
	assert.Contains(t, j, "dst="+workDir+" ", "checkout is the only rw mount")
	assert.Equal(t, 1, strings.Count(j, "type=bind,src="+root+",dst=/work "))
	assert.Contains(t, j, "src=/tmp/h.sock,dst=/run/rr/halt.sock")
	assert.NotContains(t, j, "riskrails/", "no user config or cache dir")
	assert.NotContains(t, j, ".config")
	assert.Equal(t, testImage+" claude -p", strings.Join(args[len(args)-3:], " "))
}

func TestDockerArgvRefusals(t *testing.T) {
	root := repo(t)
	_, err := DockerRunner{Root: root}.argv(root, "n", "none", true, nil)
	assert.Error(t, err, "no image")
	plain := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(plain, ".git"), []byte("gitdir: x"), 0o644))
	_, err = DockerRunner{Image: testImage}.argv(plain, "n", "none", true, nil)
	assert.Error(t, err, ".git file (worktree) stays writable")
}

func TestAgentCmd(t *testing.T) {
	c, err := DockerRunner{Runtime: "claude"}.agentCmd("sonnet", 5)
	require.NoError(t, err)
	j := strings.Join(c, " ")
	assert.Contains(t, j, "--permission-mode dontAsk --permission-prompts none")
	assert.Contains(t, j, "--max-turns 5")
	assert.NotContains(t, j, "bypass")
	c, err = DockerRunner{Runtime: "codex"}.agentCmd("gpt", 0)
	require.NoError(t, err)
	j = strings.Join(c, " ")
	assert.Contains(t, j, "--sandbox workspace-write -c approval_policy=never")
	assert.NotContains(t, j, "-a never")
	assert.NotContains(t, j, "bypass")
	_, err = DockerRunner{Runtime: "gemini"}.agentCmd("m", 0)
	assert.Error(t, err)
}

func TestCommandArgvIsSameSandbox(t *testing.T) {
	root := repo(t)
	args, err := DockerRunner{Image: testImage, Root: root}.CommandArgv("vendor/bin/phpunit")
	require.NoError(t, err)
	j := strings.Join(args, " ")
	assert.Contains(t, j, "--network none")
	assert.Contains(t, j, "dst=/work/riskrails.yaml,readonly")
	assert.True(t, strings.HasSuffix(j, testImage+" vendor/bin/phpunit"))
	assert.NotContains(t, j, " -i ")
}

func TestDockerRunWithFakeBin(t *testing.T) {
	root := repo(t)
	log := filepath.Join(t.TempDir(), "args")
	testutil.FakeBin(t, "docker", `echo "$@" >> `+log+`
cat >/dev/null
echo '{"result":"done\\nSTATUS: DONE","is_error":false,"num_turns":3,"usage":{"input_tokens":10,"output_tokens":5}}'`)
	d := DockerRunner{Image: testImage, Runtime: "claude", Root: root, Network: "rr-egress", Models: map[core.Tier]string{core.TierFast: "haiku"}}
	rep, err := d.Run(t.Context(), core.WorkerSpec{Tier: core.TierFast, Brief: "do it", MaxTurns: 3})
	require.NoError(t, err)
	assert.Equal(t, core.StatusDone, rep.Status)
	assert.EqualValues(t, 15, rep.Tokens)
	b, _ := os.ReadFile(log)
	assert.Contains(t, string(b), "--model haiku")
	assert.Contains(t, string(b), "--pull never")
	assert.Contains(t, string(b), "--network rr-egress")

	_, err = d.Run(t.Context(), core.WorkerSpec{Tier: core.TierExpert})
	assert.Error(t, err, "no model for tier")
}

func TestParseReportFailsClosed(t *testing.T) {
	assert.Equal(t, core.StatusBlocked, parseReport("claude", "garbage", "boom", nil).Status)
	assert.Equal(t, core.StatusBlocked, parseReport("claude", `{"result":"x\nSTATUS: DONE","is_error":true}`, "", nil).Status)
	assert.Equal(t, core.StatusBlocked, parseReport("claude", `{"result":"STATUS: DONE\nbut then more"}`, "", nil).Status)
	assert.Equal(t, core.StatusDone, parseReport("codex", "ok\nSTATUS: DONE\n", "", nil).Status)
}
