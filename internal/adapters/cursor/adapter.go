// Package cursor is the RiskRails runtime adapter for Cursor (facts and pinned
// docs date in docs/research/verified/cursor.md).
//
// Cursor hooks fail open by default and do not enforce `ask` in preToolUse.
// The adapter therefore renders every non-allow verdict as a deny with exit 2,
// the generated hooks.json sets failClosed on every hook, and the hook command
// is `rr guard … || exit 2`. There is no OS sandbox: Enforcement is hook_only.
package cursor

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

// Name is the runtime name used in `rr guard --runtime cursor`.
const Name = "cursor"

// events lists the hooks the adapter parses and generates.
var events = []string{"preToolUse", "beforeShellExecution", "beforeReadFile", "beforeMCPExecution", "subagentStart"}

func init() { runtimes.Register(Adapter{}) }

// Adapter implements core.RuntimeAdapter for Cursor.
type Adapter struct{}

func (Adapter) Name() string { return Name }

func (Adapter) Generators() []core.Generator { return []core.Generator{hooksGen{}} }

func (Adapter) Enforcement(context.Context, string) (core.Enforcement, error) {
	return core.EnforcementHookOnly, nil
}

type hookInput struct {
	HookEventName  string          `json:"hook_event_name"`
	Cwd            string          `json:"cwd"`
	WorkspaceRoots []string        `json:"workspace_roots"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	Command        string          `json:"command"`
	FilePath       string          `json:"file_path"`
	McpServerName  string          `json:"mcp_server_name"`
	SubagentModel  string          `json:"subagent_model"`
}

// ParseHookInput converts a Cursor hook payload to a core.ToolCall.
//
//   - beforeShellExecution and preToolUse Shell: Tool "Bash", Command.
//   - preToolUse Write: Tool "Write" with the full new content; Delete: Tool
//     "Edit" with empty Content; Read / beforeReadFile: "Read"; Grep: "Grep";
//     Task / subagentStart: "Task" (+ Model).
//   - beforeMCPExecution and preToolUse MCP:<tool>: Tool "mcp__<server>__<tool>"
//     with generic path/url/command extraction.
//   - any other event or tool, or a missing field the guard needs, is an error.
func (Adapter) ParseHookInput(event string, r io.Reader) (core.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return core.ToolCall{}, fmt.Errorf("cursor: read hook input: %w", err)
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return core.ToolCall{}, fmt.Errorf("cursor: malformed hook input: %w", err)
	}
	if !slices.Contains(events, event) {
		return core.ToolCall{}, fmt.Errorf("cursor: unsupported event %q", event)
	}
	if in.HookEventName != "" && in.HookEventName != event {
		return core.ToolCall{}, fmt.Errorf("cursor: hook_event_name %q does not match event %q", in.HookEventName, event)
	}
	cwd := cmp.Or(in.Cwd, firstOf(in.WorkspaceRoots))
	call := core.ToolCall{Runtime: Name, Event: event, Cwd: cwd, Raw: bytes.Clone(raw)}
	abs := func(p string) (string, error) {
		if p == "" {
			return "", errors.New("cursor: empty path")
		}
		if p == "~" || strings.HasPrefix(p, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("cursor: cannot expand ~: %w", err)
			}
			p = filepath.Join(home, p[1:])
		}
		if !filepath.IsAbs(p) {
			if !filepath.IsAbs(cwd) {
				return "", fmt.Errorf("cursor: relative path %q and no absolute cwd", p)
			}
			p = filepath.Join(cwd, p)
		}
		return filepath.Clean(p), nil
	}
	switch event {
	case "beforeShellExecution":
		return shell(call, in.Command)
	case "beforeReadFile":
		call.Tool = "Read"
		return withPaths(call, abs, false, in.FilePath)
	case "subagentStart":
		call.Tool, call.Model = "Task", in.SubagentModel
		return call, nil
	case "beforeMCPExecution":
		if in.ToolName == "" || in.McpServerName == "" {
			return core.ToolCall{}, errors.New("cursor: beforeMCPExecution lacks tool_name or mcp_server_name")
		}
		call.Tool = "mcp__" + in.McpServerName + "__" + in.ToolName
		return generic(call, in.ToolInput, abs)
	}
	return parsePre(call, in, abs)
}

// parsePre handles preToolUse, whose tool_input depends on tool_name.
func parsePre(call core.ToolCall, in hookInput, abs func(string) (string, error)) (core.ToolCall, error) {
	var err error
	if in.ToolName == "" {
		return core.ToolCall{}, errors.New("cursor: preToolUse lacks tool_name")
	}
	var ti struct {
		Command    string  `json:"command"`
		WorkingDir string  `json:"working_directory"`
		FilePath   string  `json:"file_path"`
		Path       string  `json:"path"`
		Content    *string `json:"content"`
		Model      string  `json:"model"`
		TargetFile string  `json:"target_file"`
		TargetDir  string  `json:"target_directory"`
		DirPath    string  `json:"dir_path"`
		Directory  string  `json:"directory"`
	}
	var contents struct {
		Contents *string `json:"contents"`
	}
	if len(in.ToolInput) > 0 && string(in.ToolInput) != "null" {
		if err := json.Unmarshal(in.ToolInput, &ti); err != nil {
			if !strings.HasPrefix(in.ToolName, "MCP:") {
				return core.ToolCall{}, fmt.Errorf("cursor: decode tool_input of %s: %w", in.ToolName, err)
			}
		}
		_ = json.Unmarshal(in.ToolInput, &contents)
	}
	files := []string{ti.FilePath, ti.Path, ti.TargetFile}
	dirs := []string{ti.Path, ti.TargetDir, ti.DirPath, ti.Directory}
	var out core.ToolCall
	out, err = preTool(call, in, ti.Command, ti.WorkingDir, ti.Model, ti.Content, contents.Contents, files, dirs, abs)
	if err != nil {
		return core.ToolCall{}, err
	}
	if out.Tool == "Bash" {
		return out, nil
	}
	return out, addLooksLikePaths(&out, in.ToolInput, abs)
}

// preTool maps one preToolUse tool to a call; files/dirs are the candidate
// path arguments (every non-empty one goes into Paths).
func preTool(call core.ToolCall, in hookInput, command, workDir, model string, content, contents *string, files, dirs []string, abs func(string) (string, error)) (core.ToolCall, error) {
	var err error
	switch {
	case in.ToolName == "Shell":
		if workDir != "" {
			if call.Cwd, err = abs(workDir); err != nil {
				return core.ToolCall{}, err
			}
		}
		return shell(call, command)
	case in.ToolName == "Write":
		call.Tool = "Write"
		body := contents
		if body == nil {
			body = content
		}
		if body == nil {
			return core.ToolCall{}, errors.New("cursor: Write has no file contents")
		}
		call.Content = *body
		return withPaths(call, abs, false, files...)
	case in.ToolName == "Delete":
		call.Tool = "Edit"
		return withPaths(call, abs, false, files...)
	case in.ToolName == "Read":
		call.Tool = "Read"
		return withPaths(call, abs, false, files...)
	case in.ToolName == "Grep":
		call.Tool = "Grep"
		return withPaths(call, abs, true, dirs...)
	case in.ToolName == "Task":
		call.Tool, call.Model = "Task", model
		return call, nil
	case strings.HasPrefix(in.ToolName, "MCP:"):
		call.Tool = "mcp__cursor__" + strings.TrimPrefix(in.ToolName, "MCP:")
		return generic(call, in.ToolInput, abs)
	}
	return core.ToolCall{}, fmt.Errorf("cursor: unsupported tool %q", in.ToolName)
}

func shell(call core.ToolCall, command string) (core.ToolCall, error) {
	if command == "" {
		return core.ToolCall{}, errors.New("cursor: empty shell command")
	}
	call.Tool, call.Command = "Bash", command
	return call, nil
}

// withPaths sets Paths to every non-empty candidate. None is an error, except
// with orCwd (searches) where it falls back to the working directory.
func withPaths(call core.ToolCall, abs func(string) (string, error), orCwd bool, candidates ...string) (core.ToolCall, error) {
	var paths []string
	for _, p := range candidates {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 && orCwd {
		paths = []string{call.Cwd}
	}
	if len(paths) == 0 {
		return core.ToolCall{}, fmt.Errorf("cursor: %s: no path", call.Tool)
	}
	for _, p := range paths {
		a, err := abs(p)
		if err != nil {
			return core.ToolCall{}, fmt.Errorf("cursor: %s: %w", call.Tool, err)
		}
		if !slices.Contains(call.Paths, a) {
			call.Paths = append(call.Paths, a)
		}
	}
	return call, nil
}

// notPath are keys whose string values are text, never paths.
var notPath = map[string]bool{
	"command": true, "content": true, "contents": true, "old_string": true, "new_string": true,
	"instruction": true, "description": true, "prompt": true, "query": true, "pattern": true,
}

// addLooksLikePaths adds every top-level string value of tool_input that looks
// like a path (/, ~, ./, ../) to Paths, whatever its key. Stricter is fine.
func addLooksLikePaths(call *core.ToolCall, input json.RawMessage, abs func(string) (string, error)) error {
	var m map[string]any
	if json.Unmarshal(input, &m) != nil {
		return nil //nolint:nilerr // not an object: nothing to scan
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s, ok := m[k].(string)
		if !ok || notPath[k] || !pathLike(s) {
			continue
		}
		a, err := abs(s)
		if err != nil {
			return fmt.Errorf("cursor: %s: %w", call.Tool, err)
		}
		if !slices.Contains(call.Paths, a) {
			call.Paths = append(call.Paths, a)
		}
	}
	return nil
}

var (
	pathKeys = []string{"path", "file_path", "paths", "file", "filename", "target", "destination"}
	urlKeys  = []string{"url", "uri"}
)

// generic fills Paths/URL/Command of an MCP call from common argument names.
// tool_input may be an object or a JSON-encoded string.
func generic(call core.ToolCall, input json.RawMessage, abs func(string) (string, error)) (core.ToolCall, error) {
	if len(input) == 0 || string(input) == "null" {
		return call, nil
	}
	var s string
	if json.Unmarshal(input, &s) == nil {
		input = json.RawMessage(s)
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return core.ToolCall{}, fmt.Errorf("cursor: decode tool_input of %s: %w", call.Tool, err)
	}
	for _, k := range pathKeys {
		var vals []string
		switch v := m[k].(type) {
		case string:
			vals = []string{v}
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					vals = append(vals, s)
				}
			}
		}
		for _, p := range vals {
			if p == "" {
				continue
			}
			a, err := abs(p)
			if err != nil {
				return core.ToolCall{}, fmt.Errorf("cursor: %s: %w", call.Tool, err)
			}
			call.Paths = append(call.Paths, a)
		}
	}
	for _, k := range urlKeys {
		if u, ok := m[k].(string); ok && u != "" && call.URL == "" {
			call.URL = u
		}
	}
	if c, ok := m["command"].(string); ok {
		call.Command = c
	}
	return call, addLooksLikePaths(&call, input, abs)
}

type hookOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// RenderHookOutput: Allow is {"permission":"allow"} with exit 0. Everything
// else is {"permission":"deny",…} plus the reason on stderr and exit 2. Ask is
// a deny on every event: preToolUse ignores ask, subagentStart treats it as
// deny, and the same call is also seen by preToolUse (deny beats ask).
func (Adapter) RenderHookOutput(event string, call core.ToolCall, v core.Verdict, stdout, stderr io.Writer) (int, error) {
	known := slices.Contains(events, event)
	if known && v.Decision == core.Allow {
		if err := json.NewEncoder(stdout).Encode(hookOutput{Permission: "allow"}); err != nil {
			return 2, err
		}
		return 0, nil
	}
	msg := "rr: " + v.Reason
	switch {
	case !known:
		msg = fmt.Sprintf("rr: denied (unsupported event %q)", event)
	case v.Decision == core.Ask:
		msg = "rr: needs approval, run it yourself: " + askTarget(call) + " (" + v.Reason + ")"
	}
	if v.Rule != "" {
		msg += " [rule: " + v.Rule + "]"
	}
	_ = json.NewEncoder(stdout).Encode(hookOutput{Permission: "deny", UserMessage: msg, AgentMessage: msg})
	if _, err := fmt.Fprintln(stderr, msg); err != nil {
		return 2, err
	}
	return 2, nil
}

func askTarget(c core.ToolCall) string {
	switch {
	case c.Command != "":
		return c.Command
	case len(c.Paths) > 0:
		return c.Tool + " " + strings.Join(c.Paths, " ")
	case c.Tool != "":
		return c.Tool
	}
	return "(the blocked action)"
}

// pathLike reports whether s starts like a path: /, ~, ./ or ../.
func pathLike(s string) bool {
	return strings.HasPrefix(s, "/") || s == "~" || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}

func firstOf(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return l[0]
}
