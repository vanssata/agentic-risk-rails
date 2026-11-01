package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func hookCtx(t *testing.T, root string) (core.GuardContext, error) {
	t.Helper()
	return guardContext(context.Background(), root, "claude")
}

func TestHookEnvLevelOnlyTightens(t *testing.T) {
	root := taskRepo(t)
	for _, tc := range []struct {
		val  string
		want core.Level
		err  bool
	}{
		{"L2", core.L2, false}, {"L3", core.L3, false}, {"L4", core.L4, false},
		{"L1", core.L1, false}, {"L0", core.L1, false}, // never loosens the host session
		{"", 0, true}, {"L5", 0, true}, {"high", 0, true}, // set but invalid ⇒ deny
	} {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv("RR_LEVEL", tc.val)
			gc, err := hookCtx(t, root)
			if tc.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, gc.Level)
		})
	}

	// the effect: ask becomes deny at L2+, and only there
	ask := core.ToolCall{Tool: "Bash", Command: "git commit -m x"}
	assert.Equal(t, core.Ask, check(context.Background(), ask, "claude").Decision)
	t.Setenv("RR_LEVEL", "L2")
	assert.Equal(t, core.Deny, check(context.Background(), ask, "claude").Decision)
	t.Setenv("RR_LEVEL", "bogus")
	v := check(context.Background(), core.ToolCall{Tool: "Read", Paths: []string{filepath.Join(root, "composer.json")}}, "claude")
	assert.Equal(t, core.Deny, v.Decision)
	assert.Equal(t, "guard.fail_closed", v.Rule)
}

func shortSock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rrh")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return filepath.Join(d, "h.sock")
}

func TestHookHaltSocket(t *testing.T) {
	root := taskRepo(t)
	read := core.ToolCall{Tool: "Read", Paths: []string{filepath.Join(root, "composer.json")}}

	t.Run("unset: nothing asked", func(t *testing.T) {
		_, err := hookCtx(t, root)
		require.NoError(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		sock := shortSock(t)
		stop, err := (&autonomy.Halter{}).Serve(sock)
		require.NoError(t, err)
		defer stop()
		t.Setenv("RR_HALT_SOCK", sock)
		assert.Equal(t, core.Allow, check(context.Background(), read, "claude").Decision)
	})
	t.Run("halt", func(t *testing.T) {
		sock := shortSock(t)
		h := &autonomy.Halter{}
		h.Poll(context.Background(), nil, 0, func(context.Context) error { return errors.New("kill switch present") }, nil)
		stop, err := h.Serve(sock)
		require.NoError(t, err)
		defer stop()
		t.Setenv("RR_HALT_SOCK", sock)
		v := check(context.Background(), read, "claude")
		assert.Equal(t, core.Deny, v.Decision)
		assert.Contains(t, v.Reason, "kill switch present")
	})
	t.Run("unreachable", func(t *testing.T) {
		t.Setenv("RR_HALT_SOCK", shortSock(t))
		assert.Equal(t, core.Deny, check(context.Background(), read, "claude").Decision)
	})
	t.Run("empty value", func(t *testing.T) {
		t.Setenv("RR_HALT_SOCK", "")
		assert.Equal(t, core.Deny, check(context.Background(), read, "claude").Decision)
	})
}

func TestHookPolicyInForceFromEnv(t *testing.T) {
	root := taskRepo(t)
	raw, err := os.ReadFile(filepath.Join(root, "riskrails.yaml"))
	require.NoError(t, err)
	tighter := strings.Replace(string(raw), "ceiling: L2", "ceiling: L1", 1)
	require.NotEqual(t, string(raw), tighter)
	n := 0
	write := func(dir, body string) string {
		n++
		p := filepath.Join(dir, "in-force"+strings.Repeat("x", n)+".yaml")
		require.NoError(t, os.WriteFile(p, []byte(body), 0o444))
		return p
	}

	t.Run("outside the checkout it is the DefaultBranch layer", func(t *testing.T) {
		t.Setenv("RR_POLICY_IN_FORCE", write(t.TempDir(), tighter))
		gc, err := hookCtx(t, root)
		require.NoError(t, err)
		assert.Equal(t, core.L1, *gc.Policy.InForce.Autonomy.Ceiling)
	})
	t.Run("without it the default branch decides", func(t *testing.T) {
		gc, err := hookCtx(t, root)
		require.NoError(t, err)
		assert.Equal(t, core.L2, *gc.Policy.InForce.Autonomy.Ceiling)
	})
	for name, set := range map[string]func(t *testing.T) string{
		"inside the checkout": func(t *testing.T) string { return write(root, tighter) },
		"symlink into the checkout": func(t *testing.T) string {
			in := write(root, tighter)
			l := filepath.Join(t.TempDir(), "link.yaml")
			require.NoError(t, os.Symlink(in, l))
			return l
		},
		"relative":     func(t *testing.T) string { return "in-force.yaml" },
		"missing":      func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.yaml") },
		"not yaml":     func(t *testing.T) string { return write(t.TempDir(), "schema: [") },
		"unknown key":  func(t *testing.T) string { return write(t.TempDir(), "schema: 1\nbogus: true\n") },
		"empty string": func(t *testing.T) string { return "" },
	} {
		t.Run("deny: "+name, func(t *testing.T) {
			t.Setenv("RR_POLICY_IN_FORCE", set(t))
			_, err := hookCtx(t, root)
			require.Error(t, err)
			v := check(context.Background(), core.ToolCall{Tool: "Read", Paths: []string{filepath.Join(root, "composer.json")}}, "claude")
			assert.Equal(t, core.Deny, v.Decision)
		})
	}
}

func TestHookDeniesOnBrokenTask(t *testing.T) {
	root := taskRepo(t)
	read := core.ToolCall{Tool: "Read", Paths: []string{filepath.Join(root, "composer.json")}}
	require.Equal(t, core.Allow, check(context.Background(), read, "claude").Decision)

	// an open journal the hook cannot understand arms nothing and allows nothing
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".rr/run"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".rr/run/t.jsonl"), []byte("not json\n"), 0o644))
	v := check(context.Background(), read, "claude")
	assert.Equal(t, core.Deny, v.Decision)
	assert.Equal(t, "guard.fail_closed", v.Rule)
}
