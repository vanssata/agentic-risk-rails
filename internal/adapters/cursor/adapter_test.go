package cursor

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// Samples are synthetic and follow docs/research/verified/cursor.md.
func sample(event string, fields map[string]any) string {
	m := map[string]any{"conversation_id": "c1", "hook_event_name": event, "workspace_roots": []string{"/ws"}}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func parse(event, s string) (core.ToolCall, error) {
	return Adapter{}.ParseHookInput(event, strings.NewReader(s))
}

func TestParse(t *testing.T) {
	pre := func(tool string, in any) string {
		return sample("preToolUse", map[string]any{"tool_name": tool, "tool_input": in, "cwd": "/ws"})
	}
	cases := []struct {
		name  string
		event string
		input string
		want  core.ToolCall
	}{
		{"pre shell", "preToolUse", pre("Shell", map[string]any{"command": "npm i", "working_directory": "/ws/app"}),
			core.ToolCall{Tool: "Bash", Command: "npm i", Cwd: "/ws/app"}},
		{"pre write", "preToolUse", pre("Write", map[string]any{"file_path": "a.txt", "contents": "hi"}),
			core.ToolCall{Tool: "Write", Paths: []string{"/ws/a.txt"}, Content: "hi", Cwd: "/ws"}},
		{"pre write empty file", "preToolUse", pre("Write", map[string]any{"path": "/ws/e", "contents": ""}),
			core.ToolCall{Tool: "Write", Paths: []string{"/ws/e"}, Cwd: "/ws"}},
		{"pre delete", "preToolUse", pre("Delete", map[string]any{"file_path": "x/../a"}),
			core.ToolCall{Tool: "Edit", Paths: []string{"/ws/a"}, Cwd: "/ws"}},
		{"pre read", "preToolUse", pre("Read", map[string]any{"file_path": "a"}),
			core.ToolCall{Tool: "Read", Paths: []string{"/ws/a"}, Cwd: "/ws"}},
		{"pre grep default", "preToolUse", pre("Grep", map[string]any{"pattern": "x"}),
			core.ToolCall{Tool: "Grep", Paths: []string{"/ws"}, Cwd: "/ws"}},
		{"pre task", "preToolUse", pre("Task", map[string]any{"model": "fast"}),
			core.ToolCall{Tool: "Task", Model: "fast", Cwd: "/ws"}},
		{"pre mcp", "preToolUse", pre("MCP:fetch", map[string]any{"url": "https://x.test"}),
			core.ToolCall{Tool: "mcp__cursor__fetch", URL: "https://x.test", Cwd: "/ws"}},
		{"shell hook", "beforeShellExecution", sample("beforeShellExecution", map[string]any{"command": "ls", "cwd": "/ws"}),
			core.ToolCall{Tool: "Bash", Command: "ls", Cwd: "/ws"}},
		{"read hook", "beforeReadFile", sample("beforeReadFile", map[string]any{"file_path": "/ws/.env", "content": "SECRET"}),
			core.ToolCall{Tool: "Read", Paths: []string{"/ws/.env"}, Cwd: "/ws"}},
		{"mcp hook string input", "beforeMCPExecution", sample("beforeMCPExecution", map[string]any{"tool_name": "get", "mcp_server_name": "srv", "tool_input": `{"path":"f"}`}),
			core.ToolCall{Tool: "mcp__srv__get", Paths: []string{"/ws/f"}, Cwd: "/ws"}},
		{"subagent", "subagentStart", sample("subagentStart", map[string]any{"subagent_model": "m1", "cwd": "/ws"}),
			core.ToolCall{Tool: "Task", Model: "m1", Cwd: "/ws"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parse(c.event, c.input)
			require.NoError(t, err)
			c.want.Runtime, c.want.Event = Name, c.event
			assert.NotEmpty(t, got.Raw)
			got.Raw = nil
			assert.Equal(t, c.want, got)
		})
	}
}

func TestParseErrorsDeny(t *testing.T) {
	cases := []struct{ name, event, input string }{
		{"not json", "preToolUse", "garbage"},
		{"empty", "preToolUse", ""},
		{"unknown event", "afterFileEdit", sample("afterFileEdit", map[string]any{"file_path": "/ws/a"})},
		{"event mismatch", "preToolUse", sample("beforeShellExecution", map[string]any{"tool_name": "Shell"})},
		{"no tool", "preToolUse", sample("preToolUse", nil)},
		{"unknown tool", "preToolUse", sample("preToolUse", map[string]any{"tool_name": "Teleport", "tool_input": map[string]any{}})},
		{"write without contents", "preToolUse", sample("preToolUse", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "/ws/a"}, "cwd": "/ws"})},
		{"write without path", "preToolUse", sample("preToolUse", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"contents": "x"}, "cwd": "/ws"})},
		{"relative no cwd", "beforeReadFile", `{"hook_event_name":"beforeReadFile","file_path":"a"}`},
		{"empty shell", "beforeShellExecution", sample("beforeShellExecution", map[string]any{"command": ""})},
		{"mcp no server", "beforeMCPExecution", sample("beforeMCPExecution", map[string]any{"tool_name": "get"})},
		{"bad tool_input", "preToolUse", sample("preToolUse", map[string]any{"tool_name": "Shell", "tool_input": []int{1}})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parse(c.event, c.input)
			assert.Error(t, err)
		})
	}
}

func TestRender(t *testing.T) {
	call := core.ToolCall{Tool: "Bash", Command: "git push"}
	cases := []struct {
		name  string
		event string
		v     core.Verdict
		code  int
		perm  string
	}{
		{"allow", "preToolUse", core.Verdict{Decision: core.Allow}, 0, "allow"},
		{"deny", "beforeShellExecution", core.Verdict{Decision: core.Deny, Reason: "nope"}, 2, "deny"},
		{"ask pre is deny", "preToolUse", core.Verdict{Decision: core.Ask, Reason: "why"}, 2, "deny"},
		{"ask shell is deny", "beforeShellExecution", core.Verdict{Decision: core.Ask, Reason: "why"}, 2, "deny"},
		{"unknown decision", "preToolUse", core.Verdict{Decision: "maybe"}, 2, "deny"},
		{"unsupported event", "afterFileEdit", core.Verdict{Decision: core.Allow}, 2, "deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code, _ := Adapter{}.RenderHookOutput(c.event, call, c.v, &out, &errb)
			assert.Equal(t, c.code, code)
			var o hookOutput
			require.NoError(t, json.Unmarshal(out.Bytes(), &o))
			assert.Equal(t, c.perm, o.Permission)
			if c.code != 0 {
				assert.Contains(t, errb.String(), "rr:")
			}
		})
	}
	var out, errb bytes.Buffer
	_, _ = Adapter{}.RenderHookOutput("preToolUse", call, core.Verdict{Decision: core.Ask, Reason: "why"}, &out, &errb)
	assert.Contains(t, errb.String(), "run it yourself: git push")
}

func TestEnforcementHookOnly(t *testing.T) {
	e, err := Adapter{}.Enforcement(context.Background(), "/repo")
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementHookOnly, e)
}

func TestGoldens(t *testing.T) {
	for _, lvl := range []core.Level{core.L1, core.L2} {
		t.Run(lvl.String(), func(t *testing.T) {
			in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: fakes.StrictPolicy(), Level: lvl}
			fs, err := hooksGen{}.Render(context.Background(), in)
			require.NoError(t, err)
			again, err := hooksGen{}.Render(context.Background(), in)
			require.NoError(t, err)
			assert.Equal(t, fs, again)
			require.Len(t, fs, 1)
			testutil.Golden(t, lvl.String()+"/hooks.json", fs[0].Content)
			var f hooksFile
			require.NoError(t, json.Unmarshal(fs[0].Content, &f))
			require.Len(t, f.Hooks, len(events))
			for e, hs := range f.Hooks {
				require.Len(t, hs, 1, e)
				assert.True(t, hs[0].FailClosed, e)
				assert.True(t, strings.HasSuffix(hs[0].Command, "|| exit 2"), e)
			}
		})
	}
}
