package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
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
	v := decide(ctx, a, event, cmd.InOrStdin())
	code, err := a.RenderHookOutput(event, v, out, errw)
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
func decide(ctx context.Context, a core.RuntimeAdapter, event string, in io.Reader) core.Verdict {
	call, err := a.ParseHookInput(event, in)
	if err != nil {
		return core.Verdict{Decision: core.Deny, Reason: "cannot parse hook input: " + err.Error(), Rule: "guard.fail_closed"}
	}
	return check(ctx, call, a.Name())
}

func check(ctx context.Context, call core.ToolCall, runtime string) core.Verdict {
	gc, err := wiring.GuardContext(ctx, repoRoot(ctx), runtime)
	if err != nil {
		return core.Verdict{Decision: core.Deny, Reason: "cannot build guard context: " + err.Error(), Rule: "guard.fail_closed"}
	}
	return guard.New().Check(ctx, call, gc)
}

// repoRoot is the git toplevel of the working directory, or the directory itself.
func repoRoot(ctx context.Context) string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	b, err := exec.CommandContext(ctx, "git", "-C", wd, "rev-parse", "--show-toplevel").Output()
	if top := strings.TrimSpace(string(b)); err == nil && top != "" {
		return top
	}
	return wd
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
