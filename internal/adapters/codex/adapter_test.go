package codex

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

// Payloads marked "observed" were captured from `codex exec` on codex-cli 0.166.0
// (docs/research/verified/codex.md); the MCP one follows the documented schema.
const (
	observedBash  = `{"session_id":"s","turn_id":"t","transcript_path":"/x/rollout.jsonl","cwd":"/ws","hook_event_name":"PreToolUse","model":"gpt-6.1-sol","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"echo hello > a.txt"},"tool_use_id":"exec-1"}`
	observedPatch = `{"session_id":"s","turn_id":"t","transcript_path":null,"cwd":"/ws","hook_event_name":"PreToolUse","model":"m","permission_mode":"default","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: b.txt\n+hi\n*** End Patch"},"tool_use_id":"exec-2"}`
	documentedMCP = `{"session_id":"s","turn_id":"t","transcript_path":null,"cwd":"/ws","hook_event_name":"PreToolUse","model":"m","permission_mode":"default","tool_name":"mcp__filesystem__read_file","tool_input":{"path":"/etc/passwd"},"tool_use_id":"call-3"}`
)

func parse(t *testing.T, payload string) (core.ToolCall, error) {
	t.Helper()
	return Adapter{}.ParseHookInput("PreToolUse", strings.NewReader(payload))
}

func TestRegistered(t *testing.T) {
	a, ok := runtimes.Lookup("codex")
	require.True(t, ok)
	assert.Equal(t, "codex", a.Name())
	assert.Len(t, a.Generators(), 2)
}

func TestParseBash(t *testing.T) {
	c, err := parse(t, observedBash)
	require.NoError(t, err)
	assert.Equal(t, "codex", c.Runtime)
	assert.Equal(t, "PreToolUse", c.Event)
	assert.Equal(t, "Bash", c.Tool)
	assert.Equal(t, "echo hello > a.txt", c.Command)
	assert.Equal(t, "/ws", c.Cwd)
	assert.JSONEq(t, observedBash, string(c.Raw))
}

func TestParseApplyPatchAdd(t *testing.T) {
	c, err := parse(t, observedPatch)
	require.NoError(t, err)
	assert.Equal(t, "Edit", c.Tool)
	assert.Equal(t, []string{"/ws/b.txt"}, c.Paths)
	assert.Equal(t, "hi\n", c.Content)
}

func TestParseMCP(t *testing.T) {
	c, err := parse(t, documentedMCP)
	require.NoError(t, err)
	assert.Equal(t, "mcp__filesystem__read_file", c.Tool)
	assert.Empty(t, c.Command)
	assert.JSONEq(t, documentedMCP, string(c.Raw))
}

func TestParseMalformed(t *testing.T) {
	for name, p := range map[string]string{
		"not json":       `{`,
		"empty":          ``,
		"no tool":        `{"cwd":"/ws","tool_input":{}}`,
		"no input":       `{"cwd":"/ws","tool_name":"Bash"}`,
		"bash no cmd":    `{"cwd":"/ws","tool_name":"Bash","tool_input":{}}`,
		"patch no cmd":   `{"cwd":"/ws","tool_name":"apply_patch","tool_input":{}}`,
		"patch rel cwd":  `{"cwd":"ws","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Delete File: a\n*** End Patch"}}`,
		"patch no begin": `{"cwd":"/ws","tool_name":"apply_patch","tool_input":{"command":"+x"}}`,
		"wrong event":    `{"hook_event_name":"PostToolUse","cwd":"/ws","tool_name":"Bash","tool_input":{"command":"x"}}`,
	} {
		_, err := parse(t, p)
		assert.Error(t, err, name)
	}
	_, err := Adapter{}.ParseHookInput("PostToolUse", strings.NewReader(observedBash))
	assert.Error(t, err)
}

func patchPayload(cwd, patch string) string {
	b := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(patch)
	return `{"cwd":"` + cwd + `","hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"` + b + `"}}`
}

func TestParseApplyPatchUpdate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "riskrails.yaml"), []byte("a: 1\nb: 2\nc: 3\nd: 4\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "x.go"), []byte("one\ntwo\nthree\n"), 0o644))

	tests := []struct {
		name, patch string
		paths       []string
		content     string
		wantErr     bool
	}{
		{"replace line", "*** Begin Patch\n*** Update File: riskrails.yaml\n@@\n a: 1\n-b: 2\n+b: 20\n c: 3\n*** End Patch",
			[]string{"riskrails.yaml"}, "a: 1\nb: 20\nc: 3\nd: 4\n", false},
		{"two hunks with context header", "*** Begin Patch\n*** Update File: riskrails.yaml\n@@\n-a: 1\n+a: 10\n@@ c: 3\n-d: 4\n+d: 40\n*** End Patch",
			[]string{"riskrails.yaml"}, "a: 10\nb: 2\nc: 3\nd: 40\n", false},
		{"pure addition appends", "*** Begin Patch\n*** Update File: riskrails.yaml\n@@\n+e: 5\n*** End Patch",
			[]string{"riskrails.yaml"}, "a: 1\nb: 2\nc: 3\nd: 4\ne: 5\n", false},
		{"delete file", "*** Begin Patch\n*** Delete File: riskrails.yaml\n*** End Patch",
			[]string{"riskrails.yaml"}, "", false},
		{"move", "*** Begin Patch\n*** Update File: src/x.go\n*** Move to: src/y.go\n@@\n-two\n+2\n*** End Patch",
			[]string{"src/x.go", "src/y.go"}, "one\n2\nthree\n", false},
		{"hunk does not apply", "*** Begin Patch\n*** Update File: riskrails.yaml\n@@\n-zzz\n+y\n*** End Patch", nil, "", true},
		{"missing file", "*** Begin Patch\n*** Update File: nope.txt\n@@\n-a\n+b\n*** End Patch", nil, "", true},
		{"two files", "*** Begin Patch\n*** Add File: a.txt\n+1\n*** Add File: b.txt\n+2\n*** End Patch", nil, "", true},
		{"bad add line", "*** Begin Patch\n*** Add File: a.txt\nnoplus\n*** End Patch", nil, "", true},
		{"absolute path", "*** Begin Patch\n*** Add File: /etc/x/../y\n+1\n*** End Patch", []string{"/etc/y"}, "1\n", false},
		{"dot dot", "*** Begin Patch\n*** Add File: ../out.txt\n+1\n*** End Patch", []string{filepath.Join(filepath.Dir(dir), "out.txt")}, "1\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parse(t, patchPayload(dir, tc.patch))
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			var want []string
			for _, p := range tc.paths {
				if !filepath.IsAbs(p) {
					p = filepath.Join(dir, p)
				}
				want = append(want, p)
			}
			assert.Equal(t, want, c.Paths)
			assert.Equal(t, tc.content, c.Content)
		})
	}
}

func TestRenderHookOutput(t *testing.T) {
	tests := []struct {
		d    core.Decision
		code int
		err  string
	}{
		{core.Allow, 0, ""},
		{core.Deny, 2, "rr: no secrets [rule: secret_reads]"},
		{core.Ask, 2, "approval required"},
		{core.Decision("bogus"), 2, "rr: no secrets"},
		{core.Decision(""), 2, "rr: no secrets"},
	}
	for _, tc := range tests {
		var so, se bytes.Buffer
		code, err := Adapter{}.RenderHookOutput("PreToolUse", core.Verdict{Decision: tc.d, Reason: "no secrets", Rule: "secret_reads"}, &so, &se)
		require.NoError(t, err)
		assert.Equal(t, tc.code, code, tc.d)
		assert.Empty(t, so.String(), "stdout stays empty: unsupported output would make the hook fail OPEN")
		if tc.err == "" {
			assert.Empty(t, se.String())
		} else {
			assert.Contains(t, se.String(), tc.err)
		}
	}
	var se bytes.Buffer
	code, err := Adapter{}.RenderHookOutput("PostToolUse", core.Verdict{Decision: core.Allow}, &bytes.Buffer{}, &se)
	assert.Error(t, err)
	assert.Equal(t, 2, code)
}

func TestEnforcement(t *testing.T) {
	old := lookPath
	t.Cleanup(func() { lookPath = old })
	lookPath = func(string) (string, error) { return "/usr/bin/bwrap", nil }
	e, err := Adapter{}.Enforcement(context.Background(), "/repo")
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementSandbox, e)

	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	e, err = Adapter{}.Enforcement(context.Background(), "/repo")
	require.NoError(t, err)
	if runtime.GOOS == "linux" {
		assert.Equal(t, core.EnforcementHookOnly, e)
	}
}
