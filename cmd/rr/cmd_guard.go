package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/guard"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
	"github.com/vanssata/agentic-risk-rails/internal/wiring"
)

// guardTimeout stays well below runtime hook timeouts: Codex hooks fail open
// on timeout, so the guard must answer (deny) before the runtime gives up.
const guardTimeout = 2 * time.Second

func init() {
	cli.Register(func() *cobra.Command {
		var runtime, event string
		var stdin bool
		c := &cobra.Command{
			Use:   "guard",
			Short: "PreToolUse hook: decide allow/ask/deny for one tool call (fail-closed)",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				ctx, cancel := context.WithTimeout(cmd.Context(), guardTimeout)
				defer cancel()
				if stdin && runtime == "" {
					return guardNeutral(ctx, cmd.InOrStdin(), cmd.OutOrStdout())
				}
				return guardRuntime(ctx, runtime, event, cmd)
			},
		}
		c.Flags().StringVar(&runtime, "runtime", "", "runtime adapter name (claude, codex)")
		c.Flags().StringVar(&event, "event", "PreToolUse", "hook event name")
		c.Flags().BoolVar(&stdin, "stdin", false, "neutral mode: read core.ToolCall JSON, write core.Verdict JSON")
		return c
	})
}

func guardRuntime(ctx context.Context, runtime, event string, cmd *cobra.Command) error {
	out, errw := cmd.OutOrStdout(), cmd.ErrOrStderr()
	a, ok := runtimes.Lookup(runtime)
	if !ok {
		return writeVerdict(out, errw, core.Verdict{Decision: core.Deny, Reason: fmt.Sprintf("unknown runtime %q", runtime), Rule: "guard.fail_closed"})
	}
	call, v := decide(ctx, a, event, cmd.InOrStdin())
	code, err := a.RenderHookOutput(event, call, v, out, errw)
	if err != nil {
		fmt.Fprintln(errw, "rr guard: render:", err)
		code = 2
	}
	if code != 0 {
		return ExitError{Code: code}
	}
	return nil
}

// decide never fails: every error becomes a deny verdict.
func decide(ctx context.Context, a core.RuntimeAdapter, event string, in io.Reader) (core.ToolCall, core.Verdict) {
	call, err := a.ParseHookInput(event, in)
	if err != nil {
		return core.ToolCall{}, core.Verdict{Decision: core.Deny, Reason: "cannot parse hook input: " + err.Error(), Rule: "guard.fail_closed"}
	}
	return call, check(ctx, call, a.Name())
}

func check(ctx context.Context, call core.ToolCall, runtime string) core.Verdict {
	gc, err := wiring.GuardContext(ctx, projectRoot(call.Cwd), runtime)
	if err != nil {
		return core.Verdict{Decision: core.Deny, Reason: "cannot build guard context: " + err.Error(), Rule: "guard.fail_closed"}
	}
	return guard.New().Check(ctx, call, gc)
}

// projectRoot is where the policy lives: $CLAUDE_PROJECT_DIR if set, else the
// OUTERMOST ancestor of the hook's working directory that holds riskrails.yaml
// or .git. An agent can create a nested repository below the project root
// (`git init sub`), so the nearest toplevel must never decide.
func projectRoot(cwd string) string {
	if d := os.Getenv("CLAUDE_PROJECT_DIR"); d != "" {
		if abs, err := filepath.Abs(d); err == nil {
			return abs
		}
	}
	if !filepath.IsAbs(cwd) {
		wd, err := os.Getwd()
		if err != nil {
			return "."
		}
		cwd = wd
	}
	root := ""
	for d := filepath.Clean(cwd); ; d = filepath.Dir(d) {
		for _, marker := range []string{"riskrails.yaml", ".git"} {
			if _, err := os.Lstat(filepath.Join(d, marker)); err == nil {
				root = d
			}
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if root == "" {
		return filepath.Clean(cwd)
	}
	return root
}

func guardNeutral(ctx context.Context, in io.Reader, out io.Writer) error {
	var call core.ToolCall
	v := core.Verdict{Decision: core.Deny, Rule: "guard.fail_closed"}
	if err := json.NewDecoder(in).Decode(&call); err != nil {
		v.Reason = "cannot parse neutral tool call: " + err.Error()
	} else {
		v = check(ctx, call, call.Runtime)
	}
	if err := json.NewEncoder(out).Encode(v); err != nil {
		return ExitError{Code: 2}
	}
	if v.Decision == core.Allow || v.Decision == core.Ask {
		return nil
	}
	return ExitError{Code: 2}
}

// writeVerdict is the neutral deny output used when no adapter can render.
func writeVerdict(out, errw io.Writer, v core.Verdict) error {
	_ = json.NewEncoder(out).Encode(v)
	fmt.Fprintln(errw, "rr guard:", v.Reason)
	return ExitError{Code: 2}
}
