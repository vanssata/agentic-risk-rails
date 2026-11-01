// Package claude is the Claude Code RuntimeAdapter: hook I/O, settings.json
// and subagent generators. Verified facts: docs/research/verified/claude-code.md.
package claude

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	goruntime "runtime"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

// Name is the runtime name used in policy (models.by_runtime) and in `rr guard --runtime`.
const Name = "claude"

// Adapter implements core.RuntimeAdapter for Claude Code.
type Adapter struct{}

func init() { runtimes.Register(Adapter{}) }

func (Adapter) Name() string { return Name }

func (Adapter) Generators() []core.Generator {
	return []core.Generator{settingsGen{}, agentsGen{}, mcpGen{}}
}

type hookOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	} `json:"hookSpecificOutput"`
}

// RenderHookOutput: PreToolUse allow/ask are JSON on stdout with exit 0; every
// other decision is a block: reason on stderr and exit 2 (exit 2 wins over any
// JSON, so a deny can never be read as allow). Other events have no decision
// schema: Allow/Ask are a silent exit 0, anything else blocks via stderr and exit 2.
func (Adapter) RenderHookOutput(event string, _ core.ToolCall, v core.Verdict, stdout, stderr io.Writer) (int, error) {
	passes := v.Decision == core.Allow || v.Decision == core.Ask
	if passes && event != "PreToolUse" {
		return 0, nil
	}
	if passes {
		var o hookOutput
		o.HookSpecificOutput.HookEventName = event
		o.HookSpecificOutput.PermissionDecision = string(v.Decision)
		o.HookSpecificOutput.PermissionDecisionReason = v.Reason
		if err := json.NewEncoder(stdout).Encode(o); err != nil {
			return 2, fmt.Errorf("write hook output: %w", err)
		}
		return 0, nil
	}
	reason := v.Reason
	if reason == "" {
		reason = "denied by RiskRails"
	}
	if _, err := fmt.Fprintln(stderr, reason); err != nil {
		return 2, fmt.Errorf("write hook output: %w", err)
	}
	return 2, nil
}

// Enforcement reports "sandbox" when the OS sandbox Claude Code uses is
// installed: bubblewrap+socat on Linux, sandbox-exec (Seatbelt) on macOS.
func (Adapter) Enforcement(context.Context, string) (core.Enforcement, error) {
	var need []string
	switch goruntime.GOOS {
	case "linux":
		need = []string{"bwrap", "socat"}
	case "darwin":
		need = []string{"sandbox-exec"}
	default:
		return core.EnforcementHookOnly, nil
	}
	for _, bin := range need {
		if _, err := exec.LookPath(bin); err != nil {
			return core.EnforcementHookOnly, nil //nolint:nilerr // a missing binary is the answer, not a failure
		}
	}
	return core.EnforcementSandbox, nil
}
