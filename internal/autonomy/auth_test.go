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

// login is an isolated login dir (like ~/.claude-rr) holding one credentials file.
func login(t *testing.T, name, content string) string {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	return dir
}

// authDocker is a fake docker that logs its args and, as a runtime refreshing its
// token would, overwrites the credentials file in the mounted login dir with $NEW.
func authDocker(t *testing.T, name, dst, newContent string) string {
	log := filepath.Join(t.TempDir(), "args")
	t.Setenv("NEW", newContent)
	testutil.FakeBin(t, "docker", `echo "$@" >> `+log+`
cat >/dev/null
for a in "$@"; do case "$a" in type=bind,src=*,dst=`+dst+`) d=${a#type=bind,src=}; d=${d%%,dst=*};; esac; done
if [ -n "$d" ] && [ -n "$NEW" ]; then printf '%s' "$NEW" > "$d/`+name+`"; fi
case "$*" in *" claude -p "*) echo '{"result":"ok\\nSTATUS: DONE","num_turns":1,"usage":{"input_tokens":1,"output_tokens":1}}';;
*) echo '{"type":"item.completed","item":{"type":"agent_message","text":"ok\\nSTATUS: DONE"}}'
echo '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}';; esac`)
	return log
}

func authRunner(t *testing.T, runtime, from string) DockerRunner {
	return DockerRunner{Image: testImage, Runtime: runtime, Root: repo(t), Network: "rr-int-x", ProxyURL: "http://p:3128",
		PolicyFile: policyFile(t), AuthFrom: from, StateDir: t.TempDir(), Models: map[core.Tier]string{core.TierBalanced: "m"}}
}

func TestSubscriptionLoginIsStagedPerContainer(t *testing.T) {
	old := `{"claudeAiOauth":{"accessToken":"a1","refreshToken":"r1"}}`
	refreshed := `{"claudeAiOauth":{"accessToken":"a2","refreshToken":"r2"}}`
	for _, tc := range []struct {
		name, newContent, want string
	}{
		{"refreshed token is written back", refreshed, refreshed},
		{"unchanged", "", old},
		{"not JSON is not written back", "garbage", old},
		{"other keys are not written back", `{"OPENAI_API_KEY":"x"}`, old},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from := login(t, ".credentials.json", old)
			log := authDocker(t, ".credentials.json", "/tmp/.claude", tc.newContent)
			d := authRunner(t, "claude", from)
			rep, err := d.Run(t.Context(), core.WorkerSpec{Tier: core.TierBalanced, Brief: "x"})
			if tc.want == old && tc.newContent != "" {
				require.Error(t, err, "a credentials file the runtime did not write blocks the task")
			} else {
				require.NoError(t, err)
				assert.Equal(t, core.StatusDone, rep.Status)
			}
			b, _ := os.ReadFile(filepath.Join(from, ".credentials.json"))
			assert.Equal(t, tc.want, string(b))
			args, _ := os.ReadFile(log)
			j := string(args)
			assert.Contains(t, j, "-e CLAUDE_CONFIG_DIR=/tmp/.claude")
			assert.NotContains(t, j, "src="+from, "the login dir itself is never mounted")
			left, _ := filepath.Glob(filepath.Join(d.StateDir, "auth-*"))
			assert.Empty(t, left, "staged copy removed after the container")
		})
	}
}

func TestCodexLoginIsTheCodexHome(t *testing.T) {
	from := login(t, "auth.json", `{"auth_mode":"chatgpt","tokens":{}}`)
	log := authDocker(t, "auth.json", codexHome, "")
	d := authRunner(t, "codex", from)
	d.CodexConfig = filepath.Join(t.TempDir(), "codex.toml")
	require.NoError(t, os.WriteFile(d.CodexConfig, []byte("x"), 0o600))
	_, err := d.Run(t.Context(), core.WorkerSpec{Tier: core.TierBalanced, Brief: "x"})
	require.NoError(t, err)
	b, _ := os.ReadFile(log)
	j := string(b)
	assert.Contains(t, j, ",dst="+codexHome+" ")
	assert.NotContains(t, j, "--tmpfs "+codexHome, "the staged login replaces the empty codex home")
	assert.Contains(t, j, "dst="+codexHome+"/config.toml,readonly", "trust config stays read-only on top")
}

func TestLoginNeverInOfflineContainers(t *testing.T) {
	d := authRunner(t, "claude", login(t, ".credentials.json", `{}`))
	d.authDir = "/x/auth-1"
	args, err := d.CommandArgv("go", "test")
	require.NoError(t, err)
	assert.NotContains(t, strings.Join(args, " "), "auth-1")
	args, err = d.argv(d.Root, "n", d.Network, true, nil)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(args, " "), "src=/x/auth-1,dst=/tmp/.claude")
}

func TestMissingLoginFailsBeforeDocker(t *testing.T) {
	log := authDocker(t, ".credentials.json", "/tmp/.claude", "")
	d := authRunner(t, "claude", t.TempDir())
	_, err := d.Run(t.Context(), core.WorkerSpec{Tier: core.TierBalanced, Brief: "x"})
	require.Error(t, err)
	_, statErr := os.Stat(log)
	assert.True(t, os.IsNotExist(statErr), "docker never ran")
}

func TestSubscriptionHosts(t *testing.T) {
	assert.Contains(t, SubscriptionHosts("claude"), "api.anthropic.com")
	assert.Contains(t, SubscriptionHosts("codex"), "chatgpt.com")
	assert.Nil(t, SubscriptionHosts("gemini"))
}

// A staged claude config dir is trusted for the workdir, or claude ignores the
// project's permissions.allow (wave 4.2 real run).
func TestClaudeLoginTrustsTheWorkdirOnly(t *testing.T) {
	d := authRunner(t, "claude", login(t, ".credentials.json", `{"claudeAiOauth":{}}`))
	dir, done, err := d.stageAuth()
	require.NoError(t, err)
	defer func() { _ = done() }()
	b, err := os.ReadFile(filepath.Join(dir, ".claude.json"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"projects":{"/work":{"hasTrustDialogAccepted":true}}}`, string(b))

	d = authRunner(t, "codex", login(t, "auth.json", `{"auth_mode":"chatgpt"}`))
	dir, done, err = d.stageAuth()
	require.NoError(t, err)
	defer func() { _ = done() }()
	_, err = os.Stat(filepath.Join(dir, ".claude.json"))
	assert.True(t, os.IsNotExist(err))
}
