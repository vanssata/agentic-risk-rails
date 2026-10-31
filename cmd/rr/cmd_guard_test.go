package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

var (
	okRT  = &fakes.Runtime{ID: "guardtest-ok", Call: core.ToolCall{Tool: "Bash", Command: "echo hi"}}
	denRT = &fakes.Runtime{ID: "guardtest-deny", Call: core.ToolCall{Tool: "Bash", Command: "rm -rf /"}}
	badRT = &fakes.Runtime{ID: "guardtest-bad", ParseErr: errors.New("garbage")}
)

func init() {
	runtimes.Register(okRT)
	runtimes.Register(denRT)
	runtimes.Register(badRT)
}

func runGuard(t *testing.T, in string, args ...string) (stdout string, err error) {
	t.Helper()
	root := cli.Root("test")
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(in))
	root.SetArgs(append([]string{"guard"}, args...))
	err = root.ExecuteContext(context.Background())
	return out.String(), err
}

func exitCode(err error) int {
	var ee ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 0
}

func TestGuardRuntime(t *testing.T) {
	out, err := runGuard(t, "{}", "--runtime", "guardtest-ok", "--event", "PreToolUse")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(out, "allow"), out)

	out, err = runGuard(t, "{}", "--runtime", "guardtest-deny", "--event", "PreToolUse")
	assert.Equal(t, 2, exitCode(err))
	assert.True(t, strings.HasPrefix(out, "deny"), out)
	require.Len(t, denRT.Rendered, 1)
	assert.Equal(t, core.Deny, denRT.Rendered[0].Decision)
}

func TestGuardParseErrorDenies(t *testing.T) {
	_, err := runGuard(t, "{}", "--runtime", "guardtest-bad", "--event", "PreToolUse")
	assert.Equal(t, 2, exitCode(err))
	require.NotEmpty(t, badRT.Rendered)
	assert.Equal(t, core.Deny, badRT.Rendered[0].Decision)
}

func TestGuardUnknownRuntimeDenies(t *testing.T) {
	out, err := runGuard(t, "{}", "--runtime", "nope", "--event", "PreToolUse")
	assert.Equal(t, 2, exitCode(err))
	var v core.Verdict
	require.NoError(t, json.Unmarshal([]byte(out), &v))
	assert.Equal(t, core.Deny, v.Decision)
}

func TestGuardStdin(t *testing.T) {
	for _, c := range []struct {
		in   string
		want core.Decision
		code int
	}{
		{`{"tool":"Bash","command":"echo hi"}`, core.Allow, 0},
		{`{"tool":"Bash","command":"ls"}`, core.Ask, 0},
		{`{"tool":"Bash","command":"rm -rf /"}`, core.Deny, 2},
		{`not json`, core.Deny, 2},
	} {
		out, err := runGuard(t, c.in, "--stdin")
		var v core.Verdict
		require.NoError(t, json.Unmarshal([]byte(out), &v), c.in)
		assert.Equal(t, c.want, v.Decision, c.in)
		assert.Equal(t, c.code, exitCode(err), c.in)
	}
}
