package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// Samples are synthetic and follow docs/research/verified/gemini.md.
func sample(tool, cwd string, input any) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "s1", "cwd": cwd, "hook_event_name": "BeforeTool",
		"tool_name": tool, "tool_input": input,
	})
	return string(b)
}

func parse(s string) (core.ToolCall, error) {
	return Adapter{}.ParseHookInput("BeforeTool", strings.NewReader(s))
}

func TestParse(t *testing.T) {
	dir := t.TempDir()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	file := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(file, []byte("one two\nthree\n"), 0o644))
	cases := []struct {
		name  string
		input string
		want  core.ToolCall
	}{
		{"shell", sample("run_shell_command", dir, map[string]any{"command": "git status"}),
			core.ToolCall{Tool: "Bash", Command: "git status", Cwd: dir}},
		{"shell dir_path", sample("run_shell_command", dir, map[string]any{"command": "ls", "dir_path": "sub"}),
			core.ToolCall{Tool: "Bash", Command: "ls", Cwd: filepath.Join(dir, "sub")}},
		{"write", sample("write_file", dir, map[string]any{"file_path": "n.txt", "content": "hi"}),
			core.ToolCall{Tool: "Write", Paths: []string{filepath.Join(dir, "n.txt")}, Content: "hi", Cwd: dir}},
		{"replace", sample("replace", dir, map[string]any{"file_path": file, "old_string": "two", "new_string": "2", "instruction": "x"}),
			core.ToolCall{Tool: "Edit", Paths: []string{file}, Content: "one 2\nthree\n", Cwd: dir}},
		{"read", sample("read_file", dir, map[string]any{"file_path": "a.txt"}),
			core.ToolCall{Tool: "Read", Paths: []string{file}, Cwd: dir}},
		{"list", sample("list_directory", dir, map[string]any{"dir_path": "."}),
			core.ToolCall{Tool: "Read", Paths: []string{dir}, Cwd: dir}},
		{"glob default path", sample("glob", dir, map[string]any{"pattern": "*.go"}),
			core.ToolCall{Tool: "Glob", Paths: []string{dir}, Cwd: dir}},
		{"grep", sample("grep_search", dir, map[string]any{"pattern": "x", "path": "src"}),
			core.ToolCall{Tool: "Grep", Paths: []string{filepath.Join(dir, "src")}, Cwd: dir}},
		{"grep dir_path", sample("grep_search", dir, map[string]any{"pattern": "x", "dir_path": "/outside/.ssh"}),
			core.ToolCall{Tool: "Grep", Paths: []string{"/outside/.ssh"}, Cwd: dir}},
		{"glob both", sample("glob", dir, map[string]any{"pattern": "*", "dir_path": "/a", "path": "b"}),
			core.ToolCall{Tool: "Glob", Paths: []string{"/a", filepath.Join(dir, "b")}, Cwd: dir}},
		{"legacy search_file_content", sample("search_file_content", dir, map[string]any{"pattern": "x"}),
			core.ToolCall{Tool: "Grep", Paths: []string{dir}, Cwd: dir}},
		{"tilde", sample("read_file", dir, map[string]any{"file_path": "~/.ssh/id_rsa"}),
			core.ToolCall{Tool: "Read", Paths: []string{filepath.Join(home, ".ssh/id_rsa")}, Cwd: dir}},
		{"unread key that looks like a path", sample("write_file", dir, map[string]any{"file_path": "a", "content": "/not/a/path", "target_dir": "../up"}),
			core.ToolCall{Tool: "Write", Paths: []string{filepath.Join(dir, "a"), filepath.Join(filepath.Dir(dir), "up")}, Content: "/not/a/path", Cwd: dir}},
		{"known passthrough", sample("web_fetch", dir, map[string]any{"prompt": "summarize https://x.test"}),
			core.ToolCall{Tool: "web_fetch", Cwd: dir}},
		{"mcp", sample("mcp_srv_fetch", dir, map[string]any{"url": "https://x.test/a", "path": "f"}),
			core.ToolCall{Tool: "mcp_srv_fetch", URL: "https://x.test/a", Paths: []string{filepath.Join(dir, "f")}, Cwd: dir}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parse(c.input)
			require.NoError(t, err)
			c.want.Runtime, c.want.Event = Name, "BeforeTool"
			assert.NotEmpty(t, got.Raw)
			got.Raw = nil
			assert.Equal(t, c.want, got)
		})
	}
}

func TestParseErrorsDeny(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(file, []byte("x x\n"), 0o644))
	cases := map[string]string{
		"not json":          "garbage",
		"empty":             "",
		"no tool":           `{"cwd":"/x","tool_input":{}}`,
		"no tool_input":     `{"cwd":"/x","tool_name":"read_file"}`,
		"event mismatch":    strings.Replace(sample("read_file", dir, map[string]any{"file_path": file}), "BeforeTool", "AfterTool", 1),
		"empty command":     sample("run_shell_command", dir, map[string]any{"command": ""}),
		"empty path":        sample("write_file", dir, map[string]any{"content": "x"}),
		"relative no cwd":   sample("read_file", "", map[string]any{"file_path": "a"}),
		"replace missing":   sample("replace", dir, map[string]any{"file_path": filepath.Join(dir, "none"), "old_string": "a", "new_string": "b"}),
		"replace not found": sample("replace", dir, map[string]any{"file_path": file, "old_string": "zzz", "new_string": "b"}),
		"replace ambiguous": sample("replace", dir, map[string]any{"file_path": file, "old_string": "x", "new_string": "b"}),
		"unknown tool":      sample("teleport", dir, map[string]any{"x": 1}),
		"no path":           sample("read_file", dir, map[string]any{}),
		"bad tool_input":    sample("write_file", dir, []int{1}),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parse(in)
			assert.Error(t, err)
		})
	}
	_, err := Adapter{}.ParseHookInput("AfterTool", strings.NewReader(sample("read_file", dir, map[string]any{"file_path": file})))
	assert.Error(t, err, "unknown event")

	got, err := parse(sample("replace", dir, map[string]any{"file_path": file, "old_string": "x", "new_string": "b", "allow_multiple": true}))
	require.NoError(t, err)
	assert.Equal(t, "b b\n", got.Content)
}

func TestRender(t *testing.T) {
	call := core.ToolCall{Tool: "Bash", Command: "git push"}
	cases := []struct {
		name   string
		event  string
		v      core.Verdict
		code   int
		stdout string
		stderr string
	}{
		{"allow", "BeforeTool", core.Verdict{Decision: core.Allow}, 0, `{"decision":"allow"}`, ""},
		{"deny", "BeforeTool", core.Verdict{Decision: core.Deny, Reason: "nope", Rule: "r1"}, 2, "", "rr: nope [rule: r1]"},
		{"ask is deny", "BeforeTool", core.Verdict{Decision: core.Ask, Reason: "why"}, 2, "", "run it yourself: git push (why)"},
		{"unknown decision", "BeforeTool", core.Verdict{Decision: "maybe"}, 2, "", "rr:"},
		{"unsupported event", "AfterTool", core.Verdict{Decision: core.Allow}, 2, "", "unsupported event"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code, _ := Adapter{}.RenderHookOutput(c.event, call, c.v, &out, &errb)
			assert.Equal(t, c.code, code)
			assert.Contains(t, out.String(), c.stdout)
			assert.Contains(t, errb.String(), c.stderr)
		})
	}
}

func TestEnforcementHookOnly(t *testing.T) {
	e, err := Adapter{}.Enforcement(context.Background(), "/repo")
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementHookOnly, e)
}

func fixturePolicy(t *testing.T) core.EffectivePolicy {
	t.Helper()
	b, err := os.ReadFile(testutil.Fixture(t, "php-symfony/riskrails.yaml"))
	require.NoError(t, err)
	p := core.StrictDefaults()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&p))
	return core.EffectivePolicy{Policy: p, InForce: p, PolicySHA: "php-symfony"}
}

func tiers() map[string]core.EffectiveTiers {
	return map[string]core.EffectiveTiers{Name: {
		Runtime: Name,
		Models:  map[core.Tier]string{core.TierBalanced: "gemini-2.5-flash", core.TierStrong: "gemini-2.5-pro"},
		Ladder:  map[core.Tier]core.Tier{core.TierFast: core.TierBalanced},
	}}
}

func render(t *testing.T, in core.SyncInput) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, g := range (Adapter{}).Generators() {
		fs, err := g.Render(context.Background(), in)
		require.NoError(t, err)
		again, err := g.Render(context.Background(), in)
		require.NoError(t, err)
		assert.Equal(t, fs, again, "generators must be pure")
		for _, f := range fs {
			out[f.Path] = string(f.Content)
		}
	}
	return out
}

func TestGoldens(t *testing.T) {
	cases := []struct {
		name   string
		policy core.EffectivePolicy
		tiers  map[string]core.EffectiveTiers
	}{
		{"strict", fakes.StrictPolicy(), nil},
		{"php-symfony", fixturePolicy(t), tiers()},
	}
	for _, c := range cases {
		for _, lvl := range []core.Level{core.L1, core.L2} {
			t.Run(c.name+"-"+lvl.String(), func(t *testing.T) {
				files := render(t, core.SyncInput{Root: "/repo", Home: "/home/test", Policy: c.policy, Tiers: c.tiers, Level: lvl})
				require.Len(t, files, 5)
				for path, body := range files {
					testutil.Golden(t, c.name+"-"+lvl.String()+"/"+strings.TrimPrefix(path, ".gemini/"), []byte(body))
				}
			})
		}
	}
}

func TestPolicySemantics(t *testing.T) {
	gen := func(l core.Level) policyDoc {
		files := render(t, core.SyncInput{Root: "/repo", Home: "/home/test", Policy: fixturePolicy(t), Level: l})
		var d policyDoc
		require.NoError(t, toml.Unmarshal([]byte(files[".gemini/policies/riskrails.toml"]), &d))
		return d
	}
	decisions := func(d policyDoc) map[string]bool {
		m := map[string]bool{}
		for _, r := range d.Rule {
			m[r.Decision] = true
		}
		return m
	}
	assert.True(t, decisions(gen(core.L1))["ask_user"])
	assert.False(t, decisions(gen(core.L2))["ask_user"], "no ask at L2")
	assert.True(t, decisions(gen(core.L2))["deny"])
}

func TestAgentsOnlyPassModels(t *testing.T) {
	files := render(t, core.SyncInput{Policy: fakes.StrictPolicy(), Tiers: tiers(), Level: core.L1})
	assert.Contains(t, files[".gemini/agents/rr-reviewer.md"], "model: gemini-2.5-pro")
	assert.Contains(t, files[".gemini/agents/rr-scout.md"], "model: gemini-2.5-flash", "fast follows the ladder")
	none := render(t, core.SyncInput{Policy: fakes.StrictPolicy(), Level: core.L1})
	for p, body := range none {
		assert.NotContains(t, body, "model:", p)
	}
}

func TestHooksFailClosedCommand(t *testing.T) {
	files := render(t, core.SyncInput{Policy: fakes.StrictPolicy(), Level: core.L1})
	assert.Contains(t, files[".gemini/settings.json"], "|| exit 2")
}
