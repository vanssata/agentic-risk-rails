// Package codex is the RiskRails runtime adapter for OpenAI Codex CLI
// (pinned codex-cli 0.166.0; facts in docs/research/verified/codex.md).
//
// Codex hooks FAIL OPEN: a crashing, slow or malformed hook lets the tool call
// run. The adapter therefore (1) renders every non-allow verdict as exit 2,
// (2) generates a hook command that turns any rr failure into exit 2, and
// (3) compiles enforcement.sandbox into a Codex permission profile, which is
// the real boundary.
package codex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

const (
	// Name is the runtime name used in `rr guard --runtime codex`.
	Name         = "codex"
	eventPreTool = "PreToolUse"
)

func init() { runtimes.Register(Adapter{}) }

// Adapter implements core.RuntimeAdapter for Codex.
type Adapter struct{}

func (Adapter) Name() string { return Name }

func (Adapter) Generators() []core.Generator {
	return []core.Generator{configGen{}, hooksGen{}}
}

// hookInput is the subset of the PreToolUse stdin schema the adapter reads.
type hookInput struct {
	HookEventName string          `json:"hook_event_name"`
	Cwd           string          `json:"cwd"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

// ParseHookInput converts a Codex PreToolUse payload to a core.ToolCall.
//
//   - Bash: Tool "Bash", Command = tool_input.command.
//   - apply_patch: Tool "Edit" (the guard's file-edit tool), Paths = every
//     file in the patch, Content = full post-edit file. A patch touching more
//     than one file fills Edits (one FileEdit each) and Paths, Content stays
//     empty; a Move reports old and new path with the new content. If any
//     file's post-edit content cannot be computed the call is an error (the
//     caller denies). Raw keeps the original payload.
//   - anything else (mcp__<server>__<tool>, update_plan, …): Tool = tool_name.
func (Adapter) ParseHookInput(event string, r io.Reader) (core.ToolCall, error) {
	if event != eventPreTool {
		return core.ToolCall{}, fmt.Errorf("codex: unsupported event %q", event)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return core.ToolCall{}, fmt.Errorf("codex: read hook input: %w", err)
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return core.ToolCall{}, fmt.Errorf("codex: malformed hook input: %w", err)
	}
	if in.HookEventName != "" && in.HookEventName != event {
		return core.ToolCall{}, fmt.Errorf("codex: hook_event_name %q does not match event %q", in.HookEventName, event)
	}
	if in.ToolName == "" || len(in.ToolInput) == 0 {
		return core.ToolCall{}, errors.New("codex: hook input lacks tool_name or tool_input")
	}
	call := core.ToolCall{Runtime: Name, Event: event, Tool: in.ToolName, Cwd: in.Cwd, Raw: json.RawMessage(raw)}
	switch in.ToolName {
	case "Bash":
		var ti struct {
			Command *string `json:"command"`
		}
		if err := json.Unmarshal(in.ToolInput, &ti); err != nil || ti.Command == nil {
			return core.ToolCall{}, errors.New("codex: Bash tool_input.command missing")
		}
		call.Command = *ti.Command
	case "apply_patch":
		if err := fillPatch(&call, in); err != nil {
			return core.ToolCall{}, err
		}
	default:
		if strings.HasPrefix(in.ToolName, "mcp__") {
			fillFromArgs(&call, in.ToolInput)
		}
	}
	return call, nil
}

// askTarget names what the human should run or approve themselves.
func askTarget(c core.ToolCall) string {
	switch {
	case c.Command != "":
		return c.Command
	case len(c.Paths) > 0:
		return "edit " + strings.Join(c.Paths, " ")
	case c.Tool != "":
		return c.Tool
	}
	return "(the blocked action)"
}

func fillPatch(call *core.ToolCall, in hookInput) error {
	var ti struct {
		Command *string `json:"command"`
	}
	if err := json.Unmarshal(in.ToolInput, &ti); err != nil || ti.Command == nil {
		return errors.New("codex: apply_patch tool_input.command missing")
	}
	if !strings.HasPrefix(in.Cwd, "/") {
		return errors.New("codex: apply_patch needs an absolute cwd")
	}
	edits, err := parsePatch(in.Cwd, *ti.Command)
	if err != nil {
		return fmt.Errorf("codex: %w", err)
	}
	call.Tool = "Edit"
	for _, e := range edits {
		if e.From != "" {
			call.Paths = append(call.Paths, e.From)
		}
		call.Paths = append(call.Paths, e.Path)
	}
	if len(edits) == 1 {
		call.Content = edits[0].Content
		return nil
	}
	for _, e := range edits {
		call.Edits = append(call.Edits, core.FileEdit{Path: e.Path, From: e.From, Content: e.Content, Delete: e.Delete})
	}
	return nil
}

var (
	pathKeys = []string{"path", "file_path", "filePath", "paths", "file", "filename", "target", "destination"}
	urlKeys  = []string{"url", "uri"}
)

// fillFromArgs extracts Paths/URL/Command from the common argument names of MCP
// tools so the guard's path and egress rules see them. Raw still has everything.
func fillFromArgs(call *core.ToolCall, input json.RawMessage) {
	var args map[string]json.RawMessage
	if json.Unmarshal(input, &args) != nil {
		return
	}
	str := func(k string) string {
		var s string
		if json.Unmarshal(args[k], &s) != nil {
			return ""
		}
		return s
	}
	for _, k := range pathKeys {
		var list []string
		if json.Unmarshal(args[k], &list) != nil {
			list = []string{str(k)}
		}
		for _, p := range list {
			if p == "" {
				continue
			}
			if !filepath.IsAbs(p) {
				p = filepath.Join(call.Cwd, p)
			}
			call.Paths = append(call.Paths, filepath.Clean(p))
		}
	}
	for _, k := range urlKeys {
		if u := str(k); u != "" && call.URL == "" {
			call.URL = u
		}
	}
	call.Command = str("command")
}

// RenderHookOutput: Allow is silent exit 0. Everything else — Deny, Ask and
// unknown decisions — is exit 2 with the reason on stderr (verified blocking
// form). Codex PreToolUse cannot ask: "ask" output makes the hook fail and the
// tool call continue, so Ask is rendered as a block whose message names the
// command for the human to run (documented limitation).
func (Adapter) RenderHookOutput(event string, call core.ToolCall, v core.Verdict, _, stderr io.Writer) (int, error) {
	if event != eventPreTool {
		_, _ = fmt.Fprintf(stderr, "rr: denied (unsupported event %q)\n", event)
		return 2, fmt.Errorf("codex: unsupported event %q", event)
	}
	if v.Decision == core.Allow {
		return 0, nil
	}
	msg := "rr: " + v.Reason
	if v.Decision == core.Ask {
		// Codex PreToolUse cannot ask; tell the human what to run themselves.
		msg = "rr: needs approval — run it yourself: " + askTarget(call) + " (" + v.Reason + ")"
	}
	if v.Rule != "" {
		msg += " [rule: " + v.Rule + "]"
	}
	if _, err := fmt.Fprintln(stderr, msg); err != nil {
		return 2, err
	}
	return 2, nil
}

var lookPath = exec.LookPath

// Enforcement: Seatbelt on macOS, bubblewrap on Linux; otherwise hooks only.
func (Adapter) Enforcement(context.Context, string) (core.Enforcement, error) {
	switch runtime.GOOS {
	case "darwin":
		return core.EnforcementSandbox, nil
	case "linux":
		if _, err := lookPath("bwrap"); err == nil {
			return core.EnforcementSandbox, nil
		}
	}
	return core.EnforcementHookOnly, nil
}
