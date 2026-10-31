package claude

import (
	"encoding/json"
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

var builtinTools = map[string]bool{
	"Bash": true, "Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "Read": true,
	"Glob": true, "Grep": true, "WebFetch": true, "WebSearch": true, "Agent": true, "Task": true,
}

// Keys scanned in tool_input of MCP and unknown tools. The result is a
// heuristic for the neutral fields; the guard also scans Raw.
var (
	genericPathKeys = []string{"path", "file_path", "filePath", "paths", "file", "filename", "target", "destination"}
	genericURLKeys  = []string{"url", "uri"}
)

// fillGeneric fills Paths/URL/Command of an MCP or unknown tool from common
// keys. Paths become absolute and Clean against cwd (via path); non-string
// values are skipped.
func fillGeneric(call *core.ToolCall, rawInput json.RawMessage, path func(string) error) error {
	if len(rawInput) == 0 || string(rawInput) == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(rawInput, &m); err != nil {
		return fmt.Errorf("decode tool_input of %s: %w", call.Tool, err)
	}
	var all []string
	for _, k := range genericPathKeys {
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
			if err := path(p); err != nil {
				return err
			}
			all = append(all, call.Paths...)
		}
	}
	call.Paths = all
	for _, k := range genericURLKeys {
		if s, ok := m[k].(string); ok && s != "" && call.URL == "" {
			call.URL = s
		}
	}
	if s, ok := m["command"].(string); ok {
		call.Command = s
	}
	return nil
}
