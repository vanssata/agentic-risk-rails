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
	"slices"
	"sort"
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
		if p == "~" || strings.HasPrefix(p, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("gemini: %s: cannot expand ~: %w", in.ToolName, err)
			}
			p = filepath.Join(home, p[1:])
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
	case "read_file", "list_directory", "read_many_files":
		call.Tool = "Read"
		err = setPaths(call, abs, ti.FilePath, ti.DirPath, ti.Path)
		if err == nil && len(call.Paths) == 0 && in.ToolName != "read_many_files" {
			err = fmt.Errorf("gemini: %s: no path", in.ToolName)
		}
	case "glob", "grep_search", "search_file_content":
		err = fillSearch(call, in, ti, abs)
	default:
		if !strings.HasPrefix(in.ToolName, "mcp_") && !passThrough[in.ToolName] {
			return fmt.Errorf("gemini: unsupported tool %q", in.ToolName)
		}
		err = fillGeneric(call, in.ToolInput, abs)
	}
	if err != nil {
		return err
	}
	if call.Tool == "Bash" {
		return nil
	}
	return addLooksLikePaths(call, in.ToolInput, abs)
}

// fillSearch handles glob and grep: dir_path and path are both searched; with
// neither the search root is the working directory.
func fillSearch(call *core.ToolCall, in hookInput, ti toolInput, abs func(string) (string, error)) error {
	call.Tool = "Grep"
	if in.ToolName == "glob" {
		call.Tool = "Glob"
	}
	err := setPaths(call, abs, ti.DirPath, ti.Path)
	if err == nil && len(call.Paths) == 0 {
		err = setPaths(call, abs, in.Cwd)
	}
	if err == nil && len(call.Paths) == 0 {
		err = fmt.Errorf("gemini: %s: no path and no cwd", in.ToolName)
	}
	return err
}

// passThrough lists Gemini built-in tools (names from packages/core/src/tools/
// definitions/base-declarations.ts) that carry no file edit; they go through
// generic extraction. Any other non-mcp_ name is an error (deny).
var passThrough = map[string]bool{
	"google_web_search": true, "web_fetch": true, "write_todos": true, "get_internal_docs": true,
	"activate_skill": true, "ask_user": true, "enter_plan_mode": true, "exit_plan_mode": true,
	"update_topic": true, "complete_task": true, "read_mcp_resource": true, "list_mcp_resources": true,
}

// setPaths appends the non-empty paths (absolute, Clean) to call.Paths.
func setPaths(call *core.ToolCall, abs func(string) (string, error), paths ...string) error {
	for _, p := range paths {
		if p == "" {
			continue
		}
		a, err := abs(p)
		if err != nil {
			return err
		}
		call.Paths = append(call.Paths, a)
	}
	return nil
}

// notPath are keys whose string values are text, never paths.
var notPath = map[string]bool{
	"command": true, "content": true, "old_string": true, "new_string": true,
	"instruction": true, "description": true, "prompt": true, "query": true, "pattern": true,
}

// addLooksLikePaths adds every top-level string value of tool_input that looks
// like a path (/, ~, ./, ../) under a key the adapter did not read. Stricter is fine.
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
			return err
		}
		if !slices.Contains(call.Paths, a) {
			call.Paths = append(call.Paths, a)
		}
	}
	return nil
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

// pathLike reports whether s starts like a path: /, ~, ./ or ../.
func pathLike(s string) bool {
	return strings.HasPrefix(s, "/") || s == "~" || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}
