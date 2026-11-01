package autonomy

import (
	"context"
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

func policyFile(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(p, []byte("schema: 1\n"), 0o600))
	return p
}

func TestDockerArgv(t *testing.T) {
	root := repo(t)
	d := DockerRunner{Image: testImage, Runtime: "claude", Root: root, Sock: "/tmp/h.sock", Level: core.L2, PolicyFile: policyFile(t)}
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
	_, err := DockerRunner{Root: root, PolicyFile: policyFile(t)}.argv(root, "n", "none", true, nil)
	assert.Error(t, err, "no image")
	plain := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(plain, ".git"), []byte("gitdir: x"), 0o644))
	_, err = DockerRunner{Image: testImage, PolicyFile: policyFile(t)}.argv(plain, "n", "none", true, nil)
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
	assert.Contains(t, j, " --json ")
	assert.NotContains(t, j, "-a never")
	assert.NotContains(t, j, "bypass")
	_, err = DockerRunner{Runtime: "gemini"}.agentCmd("m", 0)
	assert.Error(t, err)
}

func TestCommandArgvIsSameSandbox(t *testing.T) {
	root := repo(t)
	args, err := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t)}.CommandArgv("vendor/bin/phpunit")
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
	d := DockerRunner{Image: testImage, Runtime: "claude", Root: root, Network: "rr-int-x", ProxyURL: "http://rr-proxy-x:3128", PolicyFile: policyFile(t), Models: map[core.Tier]string{core.TierFast: "haiku"}}
	rep, err := d.Run(t.Context(), core.WorkerSpec{Tier: core.TierFast, Brief: "do it", MaxTurns: 3})
	require.NoError(t, err)
	assert.Equal(t, core.StatusDone, rep.Status)
	assert.EqualValues(t, 15, rep.Tokens)
	b, _ := os.ReadFile(log)
	assert.Contains(t, string(b), "--model haiku")
	assert.Contains(t, string(b), "--pull never")
	assert.Contains(t, string(b), "--network rr-int-x")

	_, err = d.Run(t.Context(), core.WorkerSpec{Tier: core.TierExpert})
	assert.Error(t, err, "no model for tier")
}

func TestParseReportFailsClosed(t *testing.T) {
	assert.Equal(t, core.StatusBlocked, parseReport("claude", "garbage", "boom", nil).Status)
	assert.Equal(t, core.StatusBlocked, parseReport("claude", `{"result":"x\nSTATUS: DONE","is_error":true}`, "", nil).Status)
	assert.Equal(t, core.StatusBlocked, parseReport("claude", `{"result":"STATUS: DONE\nbut then more"}`, "", nil).Status)
}

func TestAgentNeverOnBridgeOrHost(t *testing.T) {
	root := repo(t)
	d := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t), ProxyURL: "http://p:3128"}
	for _, n := range []string{"bridge", "host", "default", "container:abc"} {
		_, err := d.argv(root, "n", n, true, nil)
		assert.Error(t, err, n)
	}
	args, err := d.argv(root, "n", "rr-int-x", true, nil)
	require.NoError(t, err)
	j := " " + strings.Join(args, " ") + " "
	assert.Contains(t, j, " --network rr-int-x ")
	assert.Equal(t, 1, strings.Count(j, " --network "))
	for _, e := range []string{"HTTPS_PROXY=http://p:3128", "HTTP_PROXY=http://p:3128", "NO_PROXY=localhost,127.0.0.1"} {
		assert.Contains(t, j, " -e "+e+" ")
	}
	none, err := d.argv(root, "n", "none", true, nil)
	require.NoError(t, err)
	assert.NotContains(t, strings.Join(none, " "), "PROXY", "no proxy env for the offline close run")
}

func TestRunWithoutProxyIsBlocked(t *testing.T) {
	root := repo(t)
	for _, d := range []DockerRunner{
		{Network: "none", ProxyURL: "http://p:3128"}, {Network: ""}, {Network: "rr-int-x"},
	} {
		d.Image, d.Runtime, d.Root, d.PolicyFile = testImage, "claude", root, policyFile(t)
		d.Models = map[core.Tier]string{core.TierFast: "haiku"}
		rep, err := d.Run(t.Context(), core.WorkerSpec{Tier: core.TierFast})
		require.NoError(t, err)
		assert.Equal(t, core.StatusBlocked, rep.Status)
	}
}

func TestPolicyInForceMountedReadOnlyOutsideRoot(t *testing.T) {
	root := repo(t)
	pf := policyFile(t)
	d := DockerRunner{Image: testImage, Root: root, PolicyFile: pf}
	args, err := d.argv(root, "n", "none", true, nil)
	require.NoError(t, err)
	j := " " + strings.Join(args, " ") + " "
	assert.Contains(t, j, "src="+pf+",dst=/run/rr/policy.yaml,readonly ")
	assert.Contains(t, j, " -e RR_POLICY_IN_FORCE=/run/rr/policy.yaml ")
	assert.Contains(t, j, " -e RR_LEVEL=")

	_, err = DockerRunner{Image: testImage, Root: root}.argv(root, "n", "none", true, nil)
	assert.Error(t, err, "no policy in force")
	inside := filepath.Join(root, ".rr", "policy.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(inside), 0o755))
	require.NoError(t, os.WriteFile(inside, []byte("x"), 0o600))
	_, err = DockerRunner{Image: testImage, Root: root, PolicyFile: inside}.argv(root, "n", "none", true, nil)
	assert.Error(t, err, "policy file inside the checkout is agent-writable")
}

func TestParseCodexJSON(t *testing.T) {
	msg := `{"type":"item.completed","item":{"id":"i2","type":"agent_message","text":"done\nSTATUS: DONE"}}` + "\n"
	ok := `{"type":"thread.started","thread_id":"t"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"i1","type":"command_execution","command":"ls"}}
` + msg + `{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":800,"output_tokens":50,"reasoning_output_tokens":0}}
{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":0,"output_tokens":5,"reasoning_output_tokens":0}}
`
	rep := parseReport("codex", ok, "", nil)
	assert.Equal(t, core.StatusDone, rep.Status)
	assert.EqualValues(t, 1065, rep.Tokens, "input (incl. cached) + output, summed over turns")
	assert.Equal(t, 2, rep.Calls)

	for name, out := range map[string]string{
		"no turn.completed": msg,
		"no usage":          msg + `{"type":"turn.completed"}` + "\n",
		"half usage":        msg + `{"type":"turn.completed","usage":{"input_tokens":5}}` + "\n",
		"garbage mid-way":   ok + "not json\n" + ok,
		"plain text":        "ok\nSTATUS: DONE\n",
	} {
		assert.LessOrEqual(t, parseReport("codex", out, "", nil).Tokens, int64(0), name+": unknown usage is 0")
	}
	assert.Equal(t, core.StatusBlocked, parseReport("codex", ok+`{"type":"turn.failed","error":{"message":"x"}}`, "", nil).Status)
	assert.Equal(t, core.StatusBlocked, parseReport("codex", ok, "boom", assert.AnError).Status)
}

func TestExecAndCommandArgvCarryNoSocketKeysOrScope(t *testing.T) {
	root := repo(t)
	t.Setenv("ANTHROPIC_API_KEY", "k")
	d := DockerRunner{Image: testImage, Runtime: "claude", Root: root, PolicyFile: policyFile(t), Sock: "/state/halt.sock",
		ScopeFile: policyFile(t), ProxyURL: "http://p:3128"}
	cmdArgs, err := d.CommandArgv("rr", "x")
	require.NoError(t, err)
	log := filepath.Join(t.TempDir(), "args")
	testutil.FakeBin(t, "docker", `echo "$@" >> `+log)
	_, err = d.Exec(t.Context(), "rr", "run", "enforcement")
	require.NoError(t, err)
	b, _ := os.ReadFile(log)
	for name, j := range map[string]string{"CommandArgv": strings.Join(cmdArgs, " "), "Exec": string(b)} {
		assert.NotContains(t, j, "halt.sock", name+": the socket does not exist before Serve")
		assert.NotContains(t, j, "RR_HALT_SOCK", name)
		assert.NotContains(t, j, "API_KEY", name)
		assert.NotContains(t, j, "scope.json", name)
		assert.Contains(t, j, "--network none", name)
		assert.Contains(t, j, "RR_POLICY_IN_FORCE", name)
	}
}

func TestAgentGetsOnlyItsRuntimeKeyAndScopeReadOnly(t *testing.T) {
	root := repo(t)
	scope := policyFile(t)
	for rt, want := range map[string]string{"claude": "ANTHROPIC_API_KEY", "codex": "OPENAI_API_KEY"} {
		d := DockerRunner{Image: testImage, Runtime: rt, Root: root, PolicyFile: policyFile(t), ScopeFile: scope, Sock: "/s/halt.sock"}
		args, err := d.argv(root, "n", "rr-int-x", true, nil)
		require.NoError(t, err)
		j := " " + strings.Join(args, " ") + " "
		assert.Contains(t, j, " -e "+want+" ")
		assert.Equal(t, 1, strings.Count(j, "API_KEY"), rt)
		assert.Contains(t, j, "src="+scope+",dst=/run/rr/scope.json,readonly ")
		assert.Contains(t, j, " -e RR_SCOPE_FILE=/run/rr/scope.json ")
		assert.Contains(t, j, "dst=/run/rr/halt.sock")
	}
	inside := filepath.Join(root, ".rr", "scope.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(inside), 0o755))
	require.NoError(t, os.WriteFile(inside, []byte("[]"), 0o600))
	_, err := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t), ScopeFile: inside}.argv(root, "n", "none", true, nil)
	assert.Error(t, err, "scope file inside the checkout is agent-writable")
}

func TestAlwaysProtectedPathsAreReadOnlyInTheAgentContainer(t *testing.T) {
	root := repo(t)
	for _, p := range []string{".claude", ".codex", ".agents", ".rr", ".githooks"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, p), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, ".mcp.json"), []byte("{}"), 0o644))
	args, err := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t)}.argv(root, "n", "none", true, nil)
	require.NoError(t, err)
	j := " " + strings.Join(args, " ") + " "
	for _, p := range []string{"riskrails.yaml", ".git", ".github", ".claude", ".codex", ".agents", ".rr", ".githooks", ".mcp.json"} {
		assert.Contains(t, j, "dst=/work/"+p+",readonly ", p)
	}
	assert.NotContains(t, j, "dst=/work/.gemini", "absent paths are not mounted")
	assert.Contains(t, j, " --init ")
}

func TestCloseSandboxNamesContainersAndRemovesThemOnCleanup(t *testing.T) {
	root := repo(t)
	log := filepath.Join(t.TempDir(), "calls")
	testutil.FakeBin(t, "docker", `echo "$@" >> `+log)
	d := DockerRunner{Image: testImage, Root: root, PolicyFile: policyFile(t), Sock: "/s/halt.sock"}
	sb, cleanup := d.CloseSandbox()
	a1, err := sb([]string{"vendor/bin/phpunit"})
	require.NoError(t, err)
	_, err = sb([]string{"vendor/bin/phpunit", "x"})
	require.NoError(t, err)
	assert.Equal(t, "docker", a1[0])
	j := strings.Join(a1, " ")
	assert.Contains(t, j, "--init")
	assert.Contains(t, j, "--network none")
	assert.NotContains(t, j, "halt.sock")
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // the close was cancelled: containers are still removed
	cleanup(ctx)
	b, _ := os.ReadFile(log)
	assert.Equal(t, 2, strings.Count(string(b), "rm -f rr-close-"), string(b))
}
