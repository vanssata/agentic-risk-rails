package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

type hookInput struct {
	Cwd           string          `json:"cwd"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

type toolInput struct {
	Command      string     `json:"command"`
	FilePath     string     `json:"file_path"`
	NotebookPath string     `json:"notebook_path"`
	Path         string     `json:"path"`
	Content      string     `json:"content"`
	OldString    string     `json:"old_string"`
	NewString    string     `json:"new_string"`
	ReplaceAll   bool       `json:"replace_all"`
	Edits        []editSpec `json:"edits"`
	URL          string     `json:"url"`
	Model        string     `json:"model"`
}

type editSpec struct {
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`
}

// ParseHookInput converts a Claude Code hook payload into a core.ToolCall.
// Any malformed or unresolvable input is an error; the caller denies.
func (Adapter) ParseHookInput(event string, r io.Reader) (core.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return core.ToolCall{}, fmt.Errorf("read hook input: %w", err)
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return core.ToolCall{}, fmt.Errorf("decode hook input: %w", err)
	}
	if in.HookEventName != "" && in.HookEventName != event {
		return core.ToolCall{}, fmt.Errorf("hook_event_name %q does not match --event %q", in.HookEventName, event)
	}
	if in.ToolName == "" {
		return core.ToolCall{}, errors.New("hook input has no tool_name")
	}
	call := core.ToolCall{
		Runtime: Name, Event: event, Tool: in.ToolName, Cwd: in.Cwd,
		Raw: json.RawMessage(bytes.Clone(raw)),
	}
	var ti toolInput
	if len(in.ToolInput) > 0 && string(in.ToolInput) != "null" {
		// MCP and unknown tools have their own schemas: only fillGeneric reads them.
		if err := json.Unmarshal(in.ToolInput, &ti); err != nil && builtinTools[in.ToolName] {
			return core.ToolCall{}, fmt.Errorf("decode tool_input of %s: %w", in.ToolName, err)
		}
	}
	if err := fillTool(&call, ti, in.ToolInput); err != nil {
		return core.ToolCall{}, err
	}
	return call, nil
}

// fillTool sets the tool-specific fields of call from ti.
func fillTool(call *core.ToolCall, ti toolInput, rawInput json.RawMessage) error {
	path := func(p string) error {
		if p == "" {
			return fmt.Errorf("%s: empty path", call.Tool)
		}
		if !filepath.IsAbs(p) {
			if !filepath.IsAbs(call.Cwd) {
				return fmt.Errorf("%s: relative path %q and no absolute cwd", call.Tool, p)
			}
			p = filepath.Join(call.Cwd, p)
		}
		call.Paths = []string{filepath.Clean(p)}
		return nil
	}
	var err error
	switch call.Tool {
	case "Bash":
		if ti.Command == "" {
			return errors.New("bash: empty command")
		}
		call.Command = ti.Command
	case "Write":
		call.Content = ti.Content
		err = path(ti.FilePath)
	case "Edit", "MultiEdit":
		if err = path(ti.FilePath); err != nil {
			break
		}
		edits := ti.Edits
		if call.Tool == "Edit" {
			edits = []editSpec{{ti.OldString, ti.NewString, ti.ReplaceAll}}
		}
		call.Content, err = applyEdits(call.Paths[0], edits)
	case "NotebookEdit":
		err = path(ti.NotebookPath)
	case "Read":
		err = path(ti.FilePath)
	case "Glob", "Grep":
		p := ti.Path
		if p == "" {
			p = call.Cwd
		}
		err = path(p)
	case "WebFetch", "WebSearch":
		call.URL = ti.URL
	case "Agent", "Task":
		call.Model = ti.Model
	default:
		err = fillGeneric(call, rawInput, path)
	}
	return err
}

// applyEdits reads path and applies edits in order, as Claude Code would.
func applyEdits(path string, edits []editSpec) (string, error) {
	if len(edits) == 0 {
		return "", errors.New("no edits")
	}
	b, err := os.ReadFile(path)
	if err != nil && (!errors.Is(err, os.ErrNotExist) || edits[0].OldString != "") {
		return "", fmt.Errorf("read %s for edit: %w", path, err)
	}
	s := string(b)
	for i, e := range edits {
		if e.OldString == "" {
			if s != "" {
				return "", fmt.Errorf("edit %d: empty old_string on non-empty %s", i, path)
			}
			s = e.NewString
			continue
		}
		n := strings.Count(s, e.OldString)
		switch {
		case n == 0:
			return "", fmt.Errorf("edit %d: old_string not found in %s", i, path)
		case n > 1 && !e.ReplaceAll:
			return "", fmt.Errorf("edit %d: old_string not unique in %s (%d matches)", i, path, n)
		case e.ReplaceAll:
			s = strings.ReplaceAll(s, e.OldString, e.NewString)
		default:
			s = strings.Replace(s, e.OldString, e.NewString, 1)
		}
	}
	return s, nil
}
