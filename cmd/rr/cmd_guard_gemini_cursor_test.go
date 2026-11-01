package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func hookJSON(t *testing.T, event string, fields map[string]any) string {
	t.Helper()
	fields["hook_event_name"] = event
	b, err := json.Marshal(fields)
	require.NoError(t, err)
	return string(b)
}

func TestGuardGeminiEndToEnd(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"README.md": "hi\n"})
	t.Setenv("CLAUDE_PROJECT_DIR", root)
	bt := func(tool string, input map[string]any) string {
		return hookJSON(t, "BeforeTool", map[string]any{"cwd": root, "tool_name": tool, "tool_input": input})
	}
	out, err := runGuard(t, bt("run_shell_command", map[string]any{"command": "echo hi"}), "--runtime", "gemini", "--event", "BeforeTool")
	require.NoError(t, err)
	assert.Contains(t, out, `"allow"`)

	for name, in := range map[string]string{
		"rm -rf":            bt("run_shell_command", map[string]any{"command": "rm -rf /"}),
		"hook config write": bt("write_file", map[string]any{"file_path": ".gemini/settings.json", "content": "{}"}),
		"unparseable":       "not json",
		"unknown event":     hookJSON(t, "AfterTool", map[string]any{"tool_name": "read_file"}),
		"replace absent":    bt("replace", map[string]any{"file_path": "nope.txt", "old_string": "a", "new_string": "b"}),
	} {
		_, err := runGuard(t, in, "--runtime", "gemini", "--event", "BeforeTool")
		assert.Equal(t, 2, exitCode(err), name)
	}
}

func TestGuardCursorEndToEnd(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"README.md": "hi\n"})
	t.Setenv("CLAUDE_PROJECT_DIR", root)
	out, err := runGuard(t, hookJSON(t, "beforeShellExecution", map[string]any{"cwd": root, "command": "echo hi"}), "--runtime", "cursor", "--event", "beforeShellExecution")
	require.NoError(t, err)
	assert.Contains(t, out, `"permission":"allow"`)

	pre := func(tool string, input map[string]any) string {
		return hookJSON(t, "preToolUse", map[string]any{"cwd": root, "tool_name": tool, "tool_input": input})
	}
	for name, c := range map[string]struct{ event, in string }{
		"rm -rf":            {"preToolUse", pre("Shell", map[string]any{"command": "rm -rf /"})},
		"hook config write": {"preToolUse", pre("Write", map[string]any{"file_path": ".cursor/hooks.json", "contents": "{}"})},
		"unlisted":          {"preToolUse", pre("Shell", map[string]any{"command": "python3 x.py"})}, // ask => deny
		"unparseable":       {"preToolUse", "not json"},
		"bad event":         {"afterFileEdit", hookJSON(t, "afterFileEdit", map[string]any{"file_path": root + "/a"})},
	} {
		out, err := runGuard(t, c.in, "--runtime", "cursor", "--event", c.event)
		assert.Equal(t, 2, exitCode(err), name)
		assert.Contains(t, out, `"permission":"deny"`, name)
	}
}
