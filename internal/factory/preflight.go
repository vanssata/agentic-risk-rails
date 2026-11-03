package factory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// PreflightIn is what `rr task build` knows before it starts host workers
// (L0/L1; at L>=2 every worker runs in the runner's container instead).
type PreflightIn struct {
	Runtime   string // claude | codex
	Root      string // the checkout; step worktrees live outside it but inherit its trust
	ConfigDir string // $CLAUDE_CONFIG_DIR or $CODEX_HOME as the workers will see it; "" = the runtime's default
	Home      string
}

// Preflight refuses a build whose workers cannot work on this host (errata #65):
// the repo is not trusted by the runtime's config (project permissions ignored),
// or the runtime's OS sandbox cannot run a command (functional probe, as errata
// #42, no model call). A failed check is a *core.Refusal{PREFLIGHT} naming the
// fix. Tool caches are not probed: CodexRunner points GOCACHE at a writable
// place itself (see codexEnv).
func Preflight(ctx context.Context, in PreflightIn) error {
	return preflight(ctx, in, runCmd)
}

// execFn runs one command with extra environment; a non-nil error = non-zero exit.
type execFn func(ctx context.Context, env []string, name string, args ...string) error

func runCmd(ctx context.Context, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	return cmd.Run()
}

func refuse(format string, a ...any) error {
	return &core.Refusal{Code: "PREFLIGHT", Detail: fmt.Sprintf(format, a...)}
}

func preflight(ctx context.Context, in PreflightIn, ex execFn) error {
	switch in.Runtime {
	case "claude":
		if err := claudeTrusted(in); err != nil {
			return err
		}
		return claudeSandbox(ctx, ex)
	case "codex":
		return codexSandbox(ctx, in, ex)
	}
	return refuse("unknown runtime %q", in.Runtime)
}

// claudeTrusted: Claude ignores the project's permissions.allow until the repo path has
// projects[path].hasTrustDialogAccepted in <config dir>/.claude.json (~/.claude.json by
// default); worktrees inherit the main repo's path. Only the exact root counts.
func claudeTrusted(in PreflightIn) error {
	root, err := filepath.EvalSymlinks(in.Root)
	if err != nil {
		return refuse("repo root %s: %v", in.Root, err)
	}
	file := filepath.Join(in.Home, ".claude.json")
	if in.ConfigDir != "" {
		file = filepath.Join(in.ConfigDir, ".claude.json")
	}
	fix := fmt.Sprintf("run `claude` once in %s and accept the trust dialog (config file: %s)", root, file)
	raw, err := os.ReadFile(file)
	if err != nil {
		return refuse("cannot read the Claude trust state (%v): %s", err, fix)
	}
	var cfg struct {
		Projects map[string]struct {
			Trusted bool `json:"hasTrustDialogAccepted"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return refuse("cannot parse %s (%v): %s", file, err, fix)
	}
	if !cfg.Projects[root].Trusted {
		return refuse("the repo is not trusted by Claude, so project permissions are ignored: %s", fix)
	}
	return nil
}

// claudeSandbox mimics what Claude's sandbox does on Linux without a model call: bwrap,
// then a nested user namespace inside it (apply-seccomp does unshare(CLONE_NEWUSER);
// Ubuntu AppArmor `unpriv_bwrap` blocks exactly that, and a bare "bwrap exists" check
// misses it). Negative control: a write under a read-only bind must fail.
func claudeSandbox(ctx context.Context, ex execFn) error {
	if runtime.GOOS != "linux" {
		return nil // seatbelt on macOS: no probe known [U]
	}
	base := []string{"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-pid", "--die-with-parent", "--"}
	fix := "Ubuntu AppArmor unpriv_bwrap blocks nested user namespaces (anthropics/claude-code#43454); see docs/research/verified/workers.md WAVE 5"
	if err := ex(ctx, nil, "bwrap", append(base, "unshare", "-U", "-r", "true")...); err != nil {
		return refuse("Claude's sandbox cannot run a command (%v): %s", err, fix)
	}
	dir, err := os.MkdirTemp("", "rr-preflight-")
	if err != nil {
		return refuse("cannot create a probe dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := ex(ctx, nil, "bwrap", append(base, "touch", filepath.Join(dir, "x"))...); err == nil {
		return refuse("the sandbox probe does not confine writes (negative control wrote %s)", dir)
	}
	return nil
}

// codexSandbox runs `codex sandbox` (no model, no tokens) in workspace-write: a write in the
// cwd must work, a write under HOME must be refused (negative control).
func codexSandbox(ctx context.Context, in PreflightIn, ex execFn) error {
	if in.Home == "" {
		return refuse("home directory unknown: cannot run the sandbox negative control")
	}
	var env []string
	if in.ConfigDir != "" {
		env = []string{"CODEX_HOME=" + in.ConfigDir}
	}
	dir, err := os.MkdirTemp("", "rr-preflight-")
	if err != nil {
		return refuse("cannot create a probe dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sb := func(target string) error {
		return ex(ctx, env, "codex", "sandbox", "-c", "sandbox_mode=workspace-write", "-C", dir, "--", "sh", "-c", `echo x > "$1"`, "sh", target)
	}
	if err := sb("rr-preflight-ok"); err != nil {
		return refuse("Codex's sandbox cannot run a command (%v): check `codex sandbox -- true` and the host's user-namespace policy", err)
	}
	deny := filepath.Join(in.Home, ".rr-preflight-deny")
	if err := sb(deny); err == nil {
		_ = os.Remove(deny)
		return refuse("the Codex sandbox does not confine writes (a write under %s succeeded)", in.Home)
	}
	return nil
}
