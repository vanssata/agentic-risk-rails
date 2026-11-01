// Package e2e drives the built `rr` binary over a copy of testdata/php-symfony.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

var rrBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rr-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rrBin = filepath.Join(dir, "rr")
	cmd := exec.Command("go", "build", "-o", rrBin, "github.com/vanssata/agentic-risk-rails/cmd/rr")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	code := 1
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build rr:", err)
	} else {
		code = m.Run()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

const (
	lightFile = "src/Controller/HomeController.php"
	lightDecl = "behaviour=0,domain=0,novelty=0"
)

// proj is a temp checkout of the fixture plus an isolated environment.
type proj struct {
	t    *testing.T
	root string
	env  []string
}

// newProj copies the fixture, fakes php and php-cs-fixer, locks the models and
// points every config/home variable into temp dirs.
func newProj(t *testing.T) *proj {
	t.Helper()
	home := t.TempDir()
	testutil.FakeBin(t, "php", "exit 0")
	root := testutil.CopyFixture(t, "php-symfony")
	fixer := filepath.Join(root, "vendor/bin/php-cs-fixer")
	require.NoError(t, os.MkdirAll(filepath.Dir(fixer), 0o755))
	require.NoError(t, os.WriteFile(fixer, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	testutil.Git(t, root, "add", "-A")
	testutil.Git(t, root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "fixer")
	for rt, m := range map[string]map[core.Tier]string{
		"claude": {core.TierFast: "haiku", core.TierBalanced: "sonnet", core.TierStrong: "opus"},
		"codex":  {core.TierFast: "gpt-5-mini", core.TierBalanced: "gpt-5-mini", core.TierStrong: "gpt-5"},
	} {
		require.NoError(t, models.WriteLock(root, core.EffectiveTiers{Runtime: rt, Models: m}))
	}
	var env []string
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME",
			"CLAUDECODE", "RR_LEVEL", "RR_HALT_SOCK", "RR_POLICY_IN_FORCE", "CLAUDE_PROJECT_DIR", "RR_CONTRACT":
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+home+"/config", "XDG_CACHE_HOME="+home+"/cache",
		"XDG_STATE_HOME="+home+"/state", "CLAUDE_CONFIG_DIR="+home+"/claude", "CODEX_HOME="+home+"/codex",
		"CLAUDE_PROJECT_DIR="+root)
	return &proj{t: t, root: root, env: env}
}

// rr runs the binary in the project; returns stdout+stderr and the exit code.
func (p *proj) rr(args ...string) (string, int) { return p.rrIn("", args...) }

func (p *proj) rrIn(stdin string, args ...string) (string, int) {
	p.t.Helper()
	cmd := exec.Command(rrBin, args...)
	cmd.Dir = p.root
	cmd.Env = p.env
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		require.ErrorAs(p.t, err, &ee)
		code = ee.ExitCode()
	}
	return out.String(), code
}

func (p *proj) mustRR(args ...string) string {
	p.t.Helper()
	out, code := p.rr(args...)
	require.Zero(p.t, code, "rr %v: %s", args, out)
	return out
}

func (p *proj) abs(rel string) string { return filepath.Join(p.root, rel) }

func (p *proj) write(rel, body string) {
	p.t.Helper()
	require.NoError(p.t, os.WriteFile(p.abs(rel), []byte(body), 0o644))
}

func (p *proj) read(rel string) string {
	p.t.Helper()
	b, err := os.ReadFile(p.abs(rel))
	require.NoError(p.t, err)
	return string(b)
}

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// claudeHook runs `rr guard --runtime claude` with a Claude PreToolUse payload.
func (p *proj) claudeHook(tool string, input map[string]any) (string, int) {
	payload := jsonStr(map[string]any{"session_id": "s", "cwd": p.root, "hook_event_name": "PreToolUse",
		"tool_name": tool, "tool_input": input})
	return p.rrIn(payload, "guard", "--runtime", "claude", "--event", "PreToolUse")
}

// codexPatch runs `rr guard --runtime codex` with an apply_patch envelope.
func (p *proj) codexPatch(patch string) (string, int) {
	payload := jsonStr(map[string]any{"cwd": p.root, "hook_event_name": "PreToolUse",
		"tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}})
	return p.rrIn(payload, "guard", "--runtime", "codex", "--event", "PreToolUse")
}
