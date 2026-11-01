package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestEnforcementHookOnly(t *testing.T) {
	e, err := Adapter{}.Enforcement(context.Background(), t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementHookOnly, e)
}

func TestHooksGolden(t *testing.T) {
	fs, err := hooksGen{}.Render(context.Background(), core.SyncInput{})
	require.NoError(t, err)
	testutil.Golden(t, "riskrails.json", fs[0].Content)
	assert.True(t, json.Valid(fs[0].Content))
}

func TestParse(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f.txt"), []byte("one two\n"), 0o644))
	mk := func(tool, args string) string {
		return `{"cwd":` + string(mustJSON(dir)) + `,"toolName":"` + tool + `","toolArgs":` + args + `}`
	}
	ok := []struct {
		name, in string
		check    func(*testing.T, core.ToolCall)
	}{
		{"bash, args as string", mk("bash", string(mustJSON(`{"command":"ls"}`))),
			func(t *testing.T, c core.ToolCall) { assert.Equal(t, "Bash", c.Tool); assert.Equal(t, "ls", c.Command) }},
		{"bash pascal, args as object", `{"cwd":` + string(mustJSON(dir)) + `,"tool_name":"bash","tool_input":{"command":"ls"}}`,
			func(t *testing.T, c core.ToolCall) { assert.Equal(t, "ls", c.Command) }},
		{"create", mk("create", `{"path":"n.txt","file_text":"hi"}`),
			func(t *testing.T, c core.ToolCall) {
				assert.Equal(t, "Edit", c.Tool)
				assert.Equal(t, "hi", c.Content)
				assert.Equal(t, []string{filepath.Join(dir, "n.txt")}, c.Paths)
			}},
		{"str_replace", mk("edit", `{"path":"f.txt","old_str":"two","new_str":"2"}`),
			func(t *testing.T, c core.ToolCall) { assert.Equal(t, "one 2\n", c.Content) }},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			call, err := Adapter{}.ParseHookInput("preToolUse", strings.NewReader(c.in))
			require.NoError(t, err)
			c.check(t, call)
		})
	}
	for name, in := range map[string]string{
		"garbage":         `x`,
		"no tool":         `{"cwd":"/a"}`,
		"relative cwd":    `{"cwd":"a","toolName":"bash"}`,
		"unknown edit":    mk("edit", `{"path":"f.txt"}`),
		"old_str missing": mk("edit", `{"path":"f.txt","old_str":"zzz","new_str":"a"}`),
		"no path":         mk("edit", `{}`),
	} {
		_, err := Adapter{}.ParseHookInput("preToolUse", strings.NewReader(in))
		assert.Error(t, err, name)
	}
	_, err := Adapter{}.ParseHookInput("postToolUse", strings.NewReader(`{}`))
	assert.Error(t, err)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRender(t *testing.T) {
	for _, c := range []struct {
		d    core.Decision
		code int
		word string
	}{{core.Allow, 0, ""}, {core.Deny, 2, "deny"}, {core.Ask, 0, "ask"}, {core.Decision("weird"), 2, "deny"}} {
		var out, errb bytes.Buffer
		code, err := Adapter{}.RenderHookOutput("preToolUse", core.ToolCall{}, core.Verdict{Decision: c.d, Reason: "r"}, &out, &errb)
		require.NoError(t, err)
		assert.Equal(t, c.code, code, c.d)
		if c.word == "" {
			assert.Empty(t, out.String())
			continue
		}
		var m map[string]string
		require.NoError(t, json.Unmarshal(out.Bytes(), &m))
		assert.Equal(t, c.word, m["permissionDecision"])
	}
}
