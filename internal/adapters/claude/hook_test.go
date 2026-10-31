package claude

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Samples are synthetic and follow the schema verified in
// docs/research/verified/claude-code.md (https://code.claude.com/docs/en/hooks).
func sample(tool, cwd string, input any) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse",
		"tool_name": tool, "tool_input": input, "tool_use_id": "toolu_1",
	})
	return string(b)
}

func parse(t *testing.T, s string) (core.ToolCall, error) {
	t.Helper()
	return Adapter{}.ParseHookInput("PreToolUse", strings.NewReader(s))
}

func TestParseTools(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(file, []byte("one two two\n"), 0o644))
	cases := []struct {
		name  string
		input string
		check func(*testing.T, core.ToolCall)
	}{
		{"bash", sample("Bash", dir, map[string]any{"command": "git status", "timeout": 1000}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, "git status", c.Command)
			assert.Equal(t, dir, c.Cwd)
			assert.Equal(t, "claude", c.Runtime)
		}},
		{"write relative", sample("Write", dir, map[string]any{"file_path": "sub/../new.txt", "content": "hi"}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, []string{filepath.Join(dir, "new.txt")}, c.Paths)
			assert.Equal(t, "hi", c.Content)
		}},
		{"edit unique", sample("Edit", dir, map[string]any{"file_path": file, "old_string": "one", "new_string": "1"}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, "1 two two\n", c.Content)
		}},
		{"edit replace_all", sample("Edit", dir, map[string]any{"file_path": file, "old_string": "two", "new_string": "2", "replace_all": true}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, "one 2 2\n", c.Content)
		}},
		{"multiedit", sample("MultiEdit", dir, map[string]any{"file_path": file, "edits": []map[string]any{
			{"old_string": "one", "new_string": "1"}, {"old_string": "1 two", "new_string": "X"}}}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, "X two\n", c.Content)
		}},
		{"read", sample("Read", dir, map[string]any{"file_path": file}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, []string{file}, c.Paths)
		}},
		{"grep default path is cwd", sample("Grep", dir, map[string]any{"pattern": "x"}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, []string{dir}, c.Paths)
		}},
		{"glob", sample("Glob", dir, map[string]any{"pattern": "*.go", "path": "src"}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, []string{filepath.Join(dir, "src")}, c.Paths)
		}},
		{"notebook", sample("NotebookEdit", dir, map[string]any{"notebook_path": "n.ipynb", "new_source": "x"}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, []string{filepath.Join(dir, "n.ipynb")}, c.Paths)
			assert.Empty(t, c.Content)
		}},
		{"webfetch", sample("WebFetch", dir, map[string]any{"url": "https://example.com/x", "prompt": "p"}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, "https://example.com/x", c.URL)
		}},
		{"agent model", sample("Agent", dir, map[string]any{"prompt": "p", "description": "d", "subagent_type": "Explore", "model": "opus"}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, "opus", c.Model)
		}},
		{"task no model", sample("Task", dir, map[string]any{"prompt": "p"}), func(t *testing.T, c core.ToolCall) {
			assert.Empty(t, c.Model)
		}},
		{"mcp", sample("mcp__srv__tool", dir, map[string]any{"a": 1}), func(t *testing.T, c core.ToolCall) {
			assert.Equal(t, "mcp__srv__tool", c.Tool)
			assert.Empty(t, c.Paths)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			call, err := parse(t, c.input)
			require.NoError(t, err)
			assert.Equal(t, "PreToolUse", call.Event)
			assert.JSONEq(t, c.input, string(call.Raw))
			c.check(t, call)
		})
	}
}

func TestParseGenericTools(t *testing.T) {
	dir := t.TempDir()
	call, err := parse(t, sample("mcp__fs__write", dir, map[string]any{
		"path": "a/../b.txt", "filePath": "/abs/./c.txt", "paths": []any{"d.txt", 5, "e/"},
		"url": "https://x.example/y", "command": "ls", "offset": map[string]any{"weird": true},
	}))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		filepath.Join(dir, "b.txt"), "/abs/c.txt", filepath.Join(dir, "d.txt"), filepath.Join(dir, "e"),
	}, call.Paths)
	assert.Equal(t, "https://x.example/y", call.URL)
	assert.Equal(t, "ls", call.Command)
	assert.Contains(t, string(call.Raw), `"filePath"`)

	// An unknown tool whose input does not match any built-in schema still parses.
	call, err = parse(t, sample("FutureTool", dir, map[string]any{"file": "f", "edits": "not-a-list", "model": 3}))
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(dir, "f")}, call.Paths)
}

func TestParseErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(file, []byte("x x\n"), 0o644))
	for name, in := range map[string]string{
		"not json":          `{`,
		"empty":             ``,
		"no tool":           `{"hook_event_name":"PreToolUse","cwd":"/"}`,
		"wrong event":       strings.Replace(sample("Bash", dir, map[string]any{"command": "ls"}), "PreToolUse", "PostToolUse", 1),
		"bad tool_input":    `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"x"}`,
		"empty command":     sample("Bash", dir, map[string]any{"command": ""}),
		"relative no cwd":   sample("Write", "", map[string]any{"file_path": "a", "content": ""}),
		"edit not found":    sample("Edit", dir, map[string]any{"file_path": file, "old_string": "zzz", "new_string": "y"}),
		"edit not unique":   sample("Edit", dir, map[string]any{"file_path": file, "old_string": "x", "new_string": "y"}),
		"edit missing file": sample("Edit", dir, map[string]any{"file_path": filepath.Join(dir, "nope"), "old_string": "x", "new_string": "y"}),
		"read no path":      sample("Read", dir, map[string]any{}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, in)
			assert.Error(t, err)
		})
	}
}

func TestRenderHookOutput(t *testing.T) {
	cases := []struct {
		name     string
		event    string
		dec      core.Decision
		exit     int
		wantJSON string
		wantErr  string
	}{
		{"allow", "PreToolUse", core.Allow, 0, "allow", ""},
		{"ask", "PreToolUse", core.Ask, 0, "ask", ""},
		{"deny", "PreToolUse", core.Deny, 2, "", "because"},
		{"unknown", "PreToolUse", core.Decision("weird"), 2, "", "because"},
		{"zero", "PreToolUse", "", 2, "", "because"},
		{"other event allow", "SessionStart", core.Allow, 0, "", ""},
		{"other event deny blocks", "SessionStart", core.Deny, 2, "", "because"},
		{"other event unknown blocks", "Stop", core.Decision("weird"), 2, "", "because"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code, err := Adapter{}.RenderHookOutput(c.event, core.Verdict{Decision: c.dec, Reason: "because"}, &out, &errb)
			require.NoError(t, err)
			assert.Equal(t, c.exit, code)
			if c.wantJSON == "" {
				assert.Empty(t, out.String())
			} else {
				var o hookOutput
				require.NoError(t, json.Unmarshal(out.Bytes(), &o))
				assert.Equal(t, c.wantJSON, o.HookSpecificOutput.PermissionDecision)
				assert.Equal(t, "PreToolUse", o.HookSpecificOutput.HookEventName)
				assert.Empty(t, errb.String())
			}
			assert.Contains(t, errb.String(), c.wantErr)
		})
	}
}
