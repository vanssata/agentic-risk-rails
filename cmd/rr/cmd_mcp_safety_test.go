package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/mcp"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func session(t *testing.T, root string, run mcp.Runner) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := sdk.NewInMemoryTransports()
	ss, err := mcp.NewServer(root, run).Connect(ctx, st, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestMCPRejectsUnsafePaths(t *testing.T) {
	called := false
	cs := session(t, t.TempDir(), func(context.Context, ...string) (string, error) { called = true; return "", nil })
	for _, bad := range []string{"--root=/x", "-h", "../x", "/etc/passwd"} {
		for tool, key := range map[string]string{"affected": "files", "triage": "files", "research": "reports"} {
			r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: map[string]any{key: []string{bad}}})
			require.NoError(t, err)
			assert.True(t, r.IsError, "%s %s", tool, bad)
		}
	}
	assert.False(t, called, "the command must not be invoked")
}

func TestMCPAffectedUsesDoubleDash(t *testing.T) {
	var got []string
	cs := session(t, "/r", func(_ context.Context, a ...string) (string, error) { got = a; return "", nil })
	_, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "affected", Arguments: map[string]any{"files": []string{"a.php"}}})
	require.NoError(t, err)
	assert.Equal(t, []string{"affected", "--root", "/r", "--", "a.php"}, got)
}

func TestMCPResearchConfinedToRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "r.md"), []byte("x"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(outside, "r.md"), filepath.Join(root, "link.md")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "ok.md"), []byte("x"), 0o644))
	var got []string
	cs := session(t, root, func(_ context.Context, a ...string) (string, error) { got = a; return "", nil })
	call := func(p string) *sdk.CallToolResult {
		r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "research", Arguments: map[string]any{"reports": []string{p}}})
		require.NoError(t, err)
		return r
	}
	assert.True(t, call("link.md").IsError)
	assert.Nil(t, got)
	assert.False(t, call("ok.md").IsError)
	assert.Equal(t, []string{"research", "merge", "--"}, got[:3])
}

func TestMCPNeverWritesStdout(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")
	cs := session(t, root, runSelf)
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	for _, c := range []sdk.CallToolParams{
		{Name: "status", Arguments: map[string]any{}},
		{Name: "triage", Arguments: map[string]any{"files": []string{"src/Controller/HomeController.php"}}},
		{Name: "affected", Arguments: map[string]any{"files": []string{"src/Controller/HomeController.php"}}},
	} {
		_, err := cs.CallTool(context.Background(), &c)
		require.NoError(t, err)
	}
	os.Stdout = old
	require.NoError(t, w.Close())
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, string(b))
}
