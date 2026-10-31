package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// Contract tests run the real `claude` (pinned 2.1.316) and cost a few cents.
// Run: RR_CONTRACT=1 go test ./internal/adapters/claude -run Contract -v
// Credentials are COPIED into a temp CLAUDE_CONFIG_DIR; the real config dir is never written.

const pinnedVersion = "2.1.316"

type contractEnv struct {
	repo, log string
	cfg       string
}

func newContractEnv(t *testing.T, mode string) contractEnv {
	t.Helper()
	if os.Getenv("RR_CONTRACT") != "1" {
		t.Skip("set RR_CONTRACT=1 to run against the real claude binary")
	}
	bin, err := exec.LookPath("claude")
	if err != nil {
		t.Skip("claude not on PATH")
	}
	out, err := exec.Command(bin, "--version").Output()
	require.NoError(t, err)
	if !strings.HasPrefix(string(out), pinnedVersion) {
		t.Skipf("claude %q, contract pinned to %s", strings.TrimSpace(string(out)), pinnedVersion)
	}
	src := os.Getenv("RR_CLAUDE_CREDENTIALS")
	if src == "" {
		src = filepath.Join(os.Getenv("CLAUDE_CONFIG_DIR"), ".credentials.json")
	}
	cred, err := os.ReadFile(src)
	if err != nil && os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Skipf("no credentials (set RR_CLAUDE_CREDENTIALS or ANTHROPIC_API_KEY): %v", err)
	}
	cfg := t.TempDir()
	if cred != nil {
		require.NoError(t, os.WriteFile(filepath.Join(cfg, ".credentials.json"), cred, 0o600))
	}

	repo := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "schema: 1\n", "README.md": "x\n"})
	in := core.SyncInput{Root: repo, Home: t.TempDir(), Policy: fakes.StrictPolicy(), Level: core.L2}
	files, err := settingsGen{}.Render(context.Background(), in)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".claude"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repo, files[0].Path), files[0].Content, 0o644))

	log := filepath.Join(t.TempDir(), "hook.log")
	script := `cat >> "$RR_LOG"; echo >> "$RR_LOG"; echo "$@" >> "$RR_LOG"
if [ "$RR_MODE" = allow ]; then echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"fake"}}'; exit 0; fi
echo "blocked by fake rr" >&2; exit 2`
	testutil.FakeBin(t, "rr", script)
	t.Setenv("RR_LOG", log)
	t.Setenv("RR_MODE", mode)
	return contractEnv{repo: repo, log: log, cfg: cfg}
}

func (e contractEnv) run(t *testing.T, prompt string, extra ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	args := append([]string{"-p", "--max-turns", "2", "--model", "haiku", "--output-format", "json"}, extra...)
	cmd := exec.CommandContext(ctx, "claude", append(args, prompt)...)
	cmd.Dir = e.repo
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Env = append(os.Environ(), "CLAUDE_CONFIG_DIR="+e.cfg, "CLAUDECODE=", "CLAUDE_CODE_ENTRYPOINT=")
	if err := cmd.Run(); err != nil {
		t.Logf("claude exit: %v\nstderr: %s\nstdout: %s", err, errb.String(), out.String())
	}
	return out.String()
}

func TestContractHookDeniesWrite(t *testing.T) {
	e := newContractEnv(t, "deny")
	e.run(t, "Use the Write tool to create hello.txt containing hi. Do nothing else. If it fails, reply FAILED.")

	log, err := os.ReadFile(e.log)
	require.NoError(t, err, "hook never ran")
	first, _, _ := strings.Cut(string(log), "\n")
	var in map[string]any
	require.NoError(t, json.Unmarshal([]byte(first), &in), string(log))
	assert.Equal(t, "PreToolUse", in["hook_event_name"])
	assert.Equal(t, "Write", in["tool_name"])
	assert.NotEmpty(t, in["session_id"])
	ti, _ := in["tool_input"].(map[string]any)
	assert.Equal(t, filepath.Join(e.repo, "hello.txt"), evalSym(ti["file_path"]))
	assert.Equal(t, "hi", strings.TrimSpace(ti["content"].(string)))
	assert.Contains(t, string(log), "guard --runtime claude --event PreToolUse")

	call, err := Adapter{}.ParseHookInput("PreToolUse", strings.NewReader(first))
	require.NoError(t, err)
	assert.Equal(t, "Write", call.Tool)
	assert.NoFileExists(t, filepath.Join(e.repo, "hello.txt"), "Write must be blocked by exit 2")
}

// The OS sandbox (bwrap) must make riskrails.yaml read-only for Bash even if
// the hook allows the command.
func TestContractSandboxBlocksPolicyWrite(t *testing.T) {
	e := newContractEnv(t, "allow")
	// A python one-liner, not a redirection: Edit deny rules would catch a redirection
	// before the sandbox, and this test is about the OS layer.
	out := e.run(t, `Run exactly this bash command and report its output: python3 -c "open('ok.txt','w').write('1'); open('riskrails.yaml','w').write('pwned')"`, "--permission-mode", "acceptEdits")
	if strings.Contains(out, "apply-seccomp") || strings.Contains(out, "sandbox failed to start") {
		t.Skip("Claude Code's sandbox cannot start on this host (nested user namespace); EACCES not exercised")
	}
	assert.FileExists(t, filepath.Join(e.repo, "ok.txt"), "control: sandbox must still allow ordinary writes")
	b, err := os.ReadFile(filepath.Join(e.repo, "riskrails.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "schema: 1\n", string(b), "sandbox did not protect riskrails.yaml")
	log, _ := os.ReadFile(e.log)
	if !strings.Contains(string(log), "pwned") {
		t.Skip("model did not attempt the write; no evidence either way")
	}
}

func evalSym(v any) string {
	s, _ := v.(string)
	if r, err := filepath.EvalSymlinks(s); err == nil {
		return r
	}
	return s
}

// DES §4.5c premise: the Agent tool's PreToolUse input carries `model`.
func TestContractAgentInputCarriesModel(t *testing.T) {
	e := newContractEnv(t, "deny")
	e.run(t, "Call the Agent tool once with subagent_type general-purpose, model sonnet, description hi, prompt 'say hi'. If it fails, reply FAILED.")
	log, err := os.ReadFile(e.log)
	require.NoError(t, err, "hook never ran")
	first, _, _ := strings.Cut(string(log), "\n")
	call, err := Adapter{}.ParseHookInput("PreToolUse", strings.NewReader(first))
	require.NoError(t, err)
	t.Logf("tool=%s raw=%s", call.Tool, call.Raw)
	assert.Contains(t, []string{"Agent", "Task"}, call.Tool)
	assert.Equal(t, "sonnet", call.Model)
}
