package codex

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// Contract tests run the real codex binary (RR_CONTRACT=1) in a temp CODEX_HOME;
// the real ~/.codex is only read (auth.json is copied for the one model call).

func contractRepo(t *testing.T) (repo, codexHome string) {
	t.Helper()
	if os.Getenv("RR_CONTRACT") != "1" {
		t.Skip("set RR_CONTRACT=1 to run against the real codex binary")
	}
	if _, err := exec.LookPath("codex"); err != nil {
		t.Skip("codex not installed")
	}
	repo = testutil.GitRepo(t, map[string]string{
		"riskrails.yaml":     "schema: 1\n",
		".env.local":         "SECRET=1\n",
		"src/app.txt":        "app\n",
		"pkg/.env.prod":      "SECRET=2\n",
		"pkg/riskrails.yaml": "nested\n",
		".github/ci.yml":     "on: push\n",
	})
	in := core.SyncInput{Root: repo, Home: t.TempDir(), Policy: fakes.StrictPolicy(), Level: core.L2}
	for _, g := range (Adapter{}).Generators() {
		fs, err := g.Render(context.Background(), in)
		require.NoError(t, err)
		for _, f := range fs {
			dst := filepath.Join(repo, f.Path)
			require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
			require.NoError(t, os.WriteFile(dst, f.Content, 0o644))
		}
	}
	codexHome = t.TempDir()
	trust := fmt.Sprintf("[projects.%q]\ntrust_level = \"trusted\"\n", repo)
	require.NoError(t, os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(trust), 0o644))
	return repo, codexHome
}

func runCodex(t *testing.T, repo, home string, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "codex", args...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CODEX_HOME="+home)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// (a) enforcement.sandbox compiled to a permission profile is enforced by the OS sandbox.
func TestContractSandboxReadonlyAndNoRead(t *testing.T) {
	repo, home := contractRepo(t)
	script := `
echo x >> riskrails.yaml; echo "w-riskrails=$?"
echo x >> .github/ci.yml; echo "w-github=$?"
echo x > src/new.txt; echo "w-src=$?"
cat .env.local >/dev/null; echo "r-env=$?"
cat pkg/.env.prod >/dev/null; echo "r-nested-env=$?"
echo x >> pkg/riskrails.yaml; echo "w-nested-policy=$?"
`
	out, err := runCodex(t, repo, home, time.Minute, "sandbox", "sh", "-c", script)
	require.NoError(t, err, out)
	assert.Contains(t, out, "w-riskrails=2", "riskrails.yaml must be read-only: %s", out)
	assert.Contains(t, out, "w-github=2", out)
	assert.Contains(t, out, "w-src=0", "the rest of the workspace stays writable: %s", out)
	assert.Contains(t, out, "r-env=1", ".env.local must be unreadable: %s", out)
	assert.Contains(t, out, "r-nested-env=1", "slash-less secret pattern must cover any depth: %s", out)
	// Known gap (codex.md): Codex cannot express read-only for a slash-less name at any depth.
	assert.Contains(t, out, "w-nested-policy=0", "documents the residual gap: %s", out)
	assert.Contains(t, out, "Read-only file system")
	assert.Contains(t, out, "Permission denied")
	b, err := os.ReadFile(filepath.Join(repo, "riskrails.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "schema: 1\n", string(b))
}

// (b) the generated hooks.json fires for a shell command and a deny (here via a
// fake rr exiting 7, turned into 2 by `|| exit 2`) blocks it. Needs auth: the
// user's auth.json is copied into the temp CODEX_HOME.
func TestContractHookBlocksShell(t *testing.T) {
	repo, home := contractRepo(t)
	auth, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".codex", "auth.json"))
	if err != nil {
		t.Skip("no codex auth available; hook shape not exercised")
	}
	require.NoError(t, os.WriteFile(filepath.Join(home, "auth.json"), auth, 0o600))
	log := filepath.Join(t.TempDir(), "stdin.log")
	testutil.FakeBin(t, "rr", fmt.Sprintf("cat >> %s\necho 'denied by fake rr' >&2\nexit 7", log))

	out, _ := runCodex(t, repo, home, 3*time.Minute, "exec", "--dangerously-bypass-hook-trust", "--skip-git-repo-check",
		"-s", "workspace-write", "-c", "approval_policy=never", "-c", "model_reasoning_effort=low",
		"Run the shell command: echo hello > marker.txt . Then stop.")
	_, statErr := os.Stat(filepath.Join(repo, "marker.txt"))
	assert.True(t, os.IsNotExist(statErr), "denied command must not run:\n%s", out)
	assert.Contains(t, out, "denied by fake rr")

	stdin, err := os.ReadFile(log)
	require.NoError(t, err, "the hook never ran:\n%s", out)
	call, err := Adapter{}.ParseHookInput("PreToolUse", bytes.NewReader(stdin))
	require.NoError(t, err)
	assert.Equal(t, "Bash", call.Tool)
	assert.Contains(t, call.Command, "marker.txt")
}
