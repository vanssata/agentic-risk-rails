// Package gemini is the RiskRails runtime adapter for Gemini CLI (facts and
// pinned version in docs/research/verified/gemini.md).
//
// Gemini hooks FAIL OPEN on any exit code but 2, so every non-allow verdict is
// exit 2 and the generated hook command is `rr guard … || exit 2`. The
// workspace policy tier is disabled upstream, so the hook is the only
// project-level enforcement: Enforcement() is always hook_only.
package gemini

import (
	"bytes"
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

const (
	// Name is the runtime name used in `rr guard --runtime gemini`.
	Name        = "gemini"
	eventBefore = "BeforeTool"
)

func init() { runtimes.Register(Adapter{}) }

// Adapter implements core.RuntimeAdapter for Gemini CLI.
type Adapter struct{}

func (Adapter) Name() string { return Name }

func (Adapter) Generators() []core.Generator {
	return []core.Generator{settingsGen{}, policyGen{}, agentsGen{}}
}

// Enforcement: Gemini's own sandbox (docker/seatbelt) is not configured by rr.
func (Adapter) Enforcement(context.Context, string) (core.Enforcement, error) {
	return core.EnforcementHookOnly, nil
}

type hookInput struct {
	Cwd           string          `json:"cwd"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

type toolInput struct {
	Command       string `json:"command"`
	DirPath       string `json:"dir_path"`
	FilePath      string `json:"file_path"`
	Path          string `json:"path"`
	Content       string `json:"content"`
	OldString     string `json:"old_string"`
	NewString     string `json:"new_string"`
	AllowMultiple bool   `json:"allow_multiple"`
}

// ParseHookInput converts a BeforeTool payload to a core.ToolCall.
//
//   - run_shell_command: Tool "Bash", Command; Cwd follows dir_path when given.
//   - write_file: Tool "Write"; replace: Tool "Edit" with the full post-edit
//     file (read from disk, edit applied; failure is an error, so deny).
//   - read_file/list_directory: "Read"; glob/grep_search: "Glob"/"Grep".
//   - anything else (mcp_*, web_fetch, …): Tool = tool_name with generic
//     path/url/command extraction; the guard decides on unknown tools.
func (Adapter) ParseHookInput(event string, r io.Reader) (core.ToolCall, error) {
	if event != eventBefore {
		return core.ToolCall{}, fmt.Errorf("gemini: unsupported event %q", event)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return core.ToolCall{}, fmt.Errorf("gemini: read hook input: %w", err)
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return core.ToolCall{}, fmt.Errorf("gemini: malformed hook input: %w", err)
	}
	if in.HookEventName != "" && in.HookEventName != event {
		return core.ToolCall{}, fmt.Errorf("gemini: hook_event_name %q does not match event %q", in.HookEventName, event)
	}
	if in.ToolName == "" || len(in.ToolInput) == 0 || string(in.ToolInput) == "null" {
		return core.ToolCall{}, errors.New("gemini: hook input lacks tool_name or tool_input")
	}
	var ti toolInput
	if err := json.Unmarshal(in.ToolInput, &ti); err != nil {
		return core.ToolCall{}, fmt.Errorf("gemini: decode tool_input of %s: %w", in.ToolName, err)
	}
	call := core.ToolCall{Runtime: Name, Event: event, Tool: in.ToolName, Cwd: in.Cwd, Raw: bytes.Clone(raw)}
	abs := func(p string) (string, error) {
		if p == "" {
			return "", fmt.Errorf("gemini: %s: empty path", in.ToolName)
		}
		if !filepath.IsAbs(p) {
			if !filepath.IsAbs(in.Cwd) {
				return "", fmt.Errorf("gemini: %s: relative path %q and no absolute cwd", in.ToolName, p)
			}
			p = filepath.Join(in.Cwd, p)
		}
		return filepath.Clean(p), nil
	}
	if err := fillTool(&call, in, ti, abs); err != nil {
		return core.ToolCall{}, err
	}
	return call, nil
}

// fillTool sets the tool-specific fields of call.
func fillTool(call *core.ToolCall, in hookInput, ti toolInput, abs func(string) (string, error)) error {
	var err error
	setPath := func(p string) error {
		a, err := abs(p)
		call.Paths = []string{a}
		return err
	}
	switch in.ToolName {
	case "run_shell_command":
		if ti.Command == "" {
			return errors.New("gemini: run_shell_command: empty command")
		}
		call.Tool, call.Command = "Bash", ti.Command
		if ti.DirPath != "" {
			call.Cwd, err = abs(ti.DirPath)
		}
	case "write_file":
		call.Tool, call.Content = "Write", ti.Content
		err = setPath(ti.FilePath)
	case "replace":
		call.Tool = "Edit"
		if err = setPath(ti.FilePath); err == nil {
			call.Content, err = applyReplace(call.Paths[0], ti)
		}
	case "read_file":
		call.Tool = "Read"
		err = setPath(ti.FilePath)
	case "list_directory":
		call.Tool = "Read"
		err = setPath(ti.DirPath)
	case "glob", "grep_search":
		call.Tool = map[string]string{"glob": "Glob", "grep_search": "Grep"}[in.ToolName]
		p := ti.Path
		if p == "" {
			p = in.Cwd
		}
		err = setPath(p)
	default:
		err = fillGeneric(call, in.ToolInput, abs)
	}
	return err
}

// applyReplace applies Gemini's replace (exact old_string, one match unless
// allow_multiple) to the file on disk.
func applyReplace(path string, ti toolInput) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil && (!errors.Is(err, os.ErrNotExist) || ti.OldString != "") {
		return "", fmt.Errorf("gemini: read %s for replace: %w", path, err)
	}
	s := string(b)
	if ti.OldString == "" {
		if s != "" {
			return "", fmt.Errorf("gemini: empty old_string on non-empty %s", path)
		}
		return ti.NewString, nil
	}
	switch n := strings.Count(s, ti.OldString); {
	case n == 0:
		return "", fmt.Errorf("gemini: old_string not found in %s", path)
	case n > 1 && !ti.AllowMultiple:
		return "", fmt.Errorf("gemini: old_string not unique in %s (%d matches)", path, n)
	case ti.AllowMultiple:
		return strings.ReplaceAll(s, ti.OldString, ti.NewString), nil
	}
	return strings.Replace(s, ti.OldString, ti.NewString, 1), nil
}

var (
	pathKeys = []string{"path", "file_path", "dir_path", "paths", "file", "filename", "target", "destination"}
	urlKeys  = []string{"url", "uri"}
)

// fillGeneric fills Paths/URL/Command of mcp_*/unknown tools from common
// argument names; Raw still has everything.
func fillGeneric(call *core.ToolCall, input json.RawMessage, abs func(string) (string, error)) error {
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return fmt.Errorf("gemini: decode tool_input of %s: %w", call.Tool, err)
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
				return err
			}
			call.Paths = append(call.Paths, a)
		}
	}
	for _, k := range urlKeys {
		if s, ok := m[k].(string); ok && s != "" && call.URL == "" {
			call.URL = s
		}
	}
	if s, ok := m["command"].(string); ok {
		call.Command = s
	}
	return nil
}

// RenderHookOutput: Allow is exit 0 with {"decision":"allow"}. Everything else
// (Deny, Ask, unknown decisions, unsupported events) is exit 2 with the reason
// on stderr: BeforeTool hooks cannot ask, and any other exit code is a
// non-fatal warning that lets the tool run.
func (Adapter) RenderHookOutput(event string, call core.ToolCall, v core.Verdict, stdout, stderr io.Writer) (int, error) {
	if event != eventBefore {
		_, _ = fmt.Fprintf(stderr, "rr: denied (unsupported event %q)\n", event)
		return 2, fmt.Errorf("gemini: unsupported event %q", event)
	}
	if v.Decision == core.Allow {
		if _, err := fmt.Fprintln(stdout, `{"decision":"allow"}`); err != nil {
			return 2, err
		}
		return 0, nil
	}
	msg := "rr: " + v.Reason
	if v.Decision == core.Ask {
		msg = "rr: needs approval, run it yourself: " + askTarget(call) + " (" + v.Reason + ")"
	}
	if v.Rule != "" {
		msg += " [rule: " + v.Rule + "]"
	}
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
