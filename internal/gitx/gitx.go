// Package gitx runs git hardened for a repo the agent may have poisoned.
//
// rr runs git from hook, verify and factory processes OUTSIDE the agent
// sandbox (errata #16, #24). Every config key that can make git execute a
// program is neutralised with `-c` (highest precedence), global/system config
// and system attributes are disabled, and no GIT_* variable is inherited.
// Callers that operate on a worker-controlled work tree must also pin
// --git-dir/--work-tree and refuse filter/merge attributes (internal/factory).
package gitx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Hardening is prepended to every git invocation.
var Hardening = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.pager=cat",
	"-c", "core.sshCommand=false",
	"-c", "core.askPass=false",
	"-c", "core.alternateRefsCommand=",
	"-c", "core.untrackedCache=false",
	"-c", "core.attributesFile=/dev/null",
	"-c", "protocol.allow=never",
	"-c", "credential.helper=",
	"-c", "diff.external=",
	"--no-pager",
}

// Env is a minimal environment: no inherited GIT_* variables (GIT_DIR,
// GIT_CONFIG_*, GIT_EXEC_PATH …), no global/system config or attributes.
func Env() []string {
	env := []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"LC_ALL=C",
	}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "SYSTEMROOT"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// Run runs hardened git with args (which include -C or --git-dir as needed)
// and returns stdout. stdin may be empty.
func Run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	return run(ctx, Env(), stdin, args)
}

// RunIndex is Run with GIT_INDEX_FILE=indexFile (absolute) added to the
// otherwise stripped environment: a pre-commit hook of `git commit -a` or
// `git commit -- <path>` must read git's temporary index, not .git/index.
func RunIndex(ctx context.Context, indexFile, stdin string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(indexFile) {
		return nil, fmt.Errorf("git index file %q is not absolute", indexFile)
	}
	return run(ctx, append(Env(), "GIT_INDEX_FILE="+indexFile), stdin, args)
}

func run(ctx context.Context, env []string, stdin string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append(append([]string{}, Hardening...), args...)...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", subcommand(args), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// subcommand names the git subcommand for error messages, skipping global
// options and the values of -C/-c.
func subcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-C" || a == "-c":
			i++
		case !strings.HasPrefix(a, "-"):
			return a
		}
	}
	return "?"
}
