// Package copilot is the adapter for GitHub Copilot (CLI and cloud agent).
// Repo hooks in .github/hooks/*.json run preToolUse command hooks that fail
// closed and deny on exit 2 (docs/research/verified/degrade.md; documented,
// not observed on a binary; hook timeouts fail OPEN, so the guard answers
// within its own 2 s). There is no OS sandbox ⇒ Enforcement is hook_only,
// autonomy ≤ L1. Tool names and file-tool arguments are [U]: any payload the
// adapter does not understand is an error, hence a deny.
package copilot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

// Name is the runtime name used in `rr guard --runtime copilot`.
const Name = "copilot"

func init() { runtimes.Register(Adapter{}) }

// Adapter implements core.RuntimeAdapter for Copilot.
type Adapter struct{}

func (Adapter) Name() string { return Name }

func (Adapter) Generators() []core.Generator { return []core.Generator{hooksGen{}} }

// Enforcement: hooks only; Copilot has no OS sandbox we configure.
func (Adapter) Enforcement(context.Context, string) (core.Enforcement, error) {
	return core.EnforcementHookOnly, nil
}

// input holds both documented spellings (camelCase and VS Code PascalCase).
type input struct {
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"toolName"`
	ToolArgs  json.RawMessage `json:"toolArgs"`
	ToolName2 string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type args struct {
	Command  string `json:"command"`
	Path     string `json:"path"`
	FileText string `json:"file_text"`
	OldStr   string `json:"old_str"`
	NewStr   string `json:"new_str"`
}

// ParseHookInput: bash ⇒ Tool "Bash"; edit/create/write ⇒ Tool "Edit" with the
// full post-edit content (file_text, or old_str→new_str applied once to the
// current file); other tools keep their name and path.
func (Adapter) ParseHookInput(event string, r io.Reader) (core.ToolCall, error) {
	if event != "preToolUse" && event != "PreToolUse" {
		return core.ToolCall{}, fmt.Errorf("copilot: unsupported event %q", event)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return core.ToolCall{}, fmt.Errorf("copilot: read hook input: %w", err)
	}
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return core.ToolCall{}, fmt.Errorf("copilot: malformed hook input: %w", err)
	}
	name, rawArgs := in.ToolName, in.ToolArgs
	if name == "" {
		name, rawArgs = in.ToolName2, in.ToolInput
	}
	if name == "" || !filepath.IsAbs(in.Cwd) {
		return core.ToolCall{}, errors.New("copilot: hook input lacks toolName or absolute cwd")
	}
	var a args
	if s := strings.TrimSpace(string(rawArgs)); s != "" && s != "null" {
		if strings.HasPrefix(s, `"`) { // toolArgs may be a JSON-encoded string
			var enc string
			if err := json.Unmarshal(rawArgs, &enc); err != nil {
				return core.ToolCall{}, fmt.Errorf("copilot: toolArgs: %w", err)
			}
			rawArgs = json.RawMessage(enc)
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return core.ToolCall{}, fmt.Errorf("copilot: toolArgs: %w", err)
		}
	}
	call := core.ToolCall{Runtime: Name, Event: event, Tool: name, Cwd: in.Cwd, Raw: json.RawMessage(raw)}
	if a.Path != "" {
		call.Paths = []string{abs(in.Cwd, a.Path)}
	}
	switch name {
	case "bash":
		call.Tool, call.Command = "Bash", a.Command
	case "edit", "create", "write":
		call.Tool = "Edit"
		if len(call.Paths) != 1 {
			return core.ToolCall{}, errors.New("copilot: file tool without path")
		}
		call.Content, err = content(call.Paths[0], a)
		if err != nil {
			return core.ToolCall{}, err
		}
	}
	return call, nil
}

func abs(cwd, p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

func content(path string, a args) (string, error) {
	if a.FileText != "" {
		return a.FileText, nil
	}
	if a.OldStr == "" {
		return "", errors.New("copilot: cannot compute post-edit content")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("copilot: %w", err)
	}
	if strings.Count(string(b), a.OldStr) != 1 {
		return "", errors.New("copilot: old_str is not unique in the file")
	}
	return strings.Replace(string(b), a.OldStr, a.NewStr, 1), nil
}

// RenderHookOutput: allow is silent; ask is a JSON ask; everything else is a
// JSON deny plus exit 2 (exit 2 always denies).
func (Adapter) RenderHookOutput(_ string, _ core.ToolCall, v core.Verdict, stdout, stderr io.Writer) (int, error) {
	if v.Decision == core.Allow {
		return 0, nil
	}
	d, code := "deny", 2
	if v.Decision == core.Ask {
		d, code = "ask", 0
	}
	reason := "rr: " + v.Reason
	if v.Rule != "" {
		reason += " [rule: " + v.Rule + "]"
	}
	out, err := json.Marshal(map[string]string{"permissionDecision": d, "permissionDecisionReason": reason})
	if err != nil {
		return 2, err
	}
	if _, err := fmt.Fprintln(stdout, string(out)); err != nil {
		return 2, err
	}
	if code != 0 {
		fmt.Fprintln(stderr, reason)
	}
	return code, nil
}

type hooksGen struct{}

func (hooksGen) Name() string { return "copilot" }

// Render: `|| exit 2` turns any rr failure (missing binary, crash) into a deny.
func (hooksGen) Render(context.Context, core.SyncInput) ([]core.File, error) {
	const cfg = `{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "rr guard --runtime copilot --event preToolUse || exit 2"
      }
    ]
  }
}
`
	return []core.File{{Path: ".github/hooks/riskrails.json", Content: []byte(cfg)}}, nil
}
