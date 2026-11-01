package mcp_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/mcp"
)

func connect(t *testing.T, root string, run mcp.Runner) *sdk.ClientSession {
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

func research(t *testing.T, cs *sdk.ClientSession, p string) *sdk.CallToolResult {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "research", Arguments: map[string]any{"reports": []string{p}}})
	require.NoError(t, err)
	return r
}

func errText(r *sdk.CallToolResult) string {
	if len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].(*sdk.TextContent).Text
}

// The generated settings auto-allow mcp__rr__*; that is only safe for exactly these tools.
func TestServerExposesExactlyTheReadOnlyTools(t *testing.T) {
	cs := connect(t, t.TempDir(), nil)
	var names []string
	for tl, err := range cs.Tools(context.Background(), nil) {
		require.NoError(t, err)
		names = append(names, tl.Name)
	}
	assert.ElementsMatch(t, []string{"triage", "research", "status"}, names)
}

func TestResearchRefusesSecretFilesWithoutContent(t *testing.T) {
	root := t.TempDir()
	secret := "DATABASE_URL=postgres://app:Hunter2pw@db/prod\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, ".env"), []byte(secret), 0o600))
	called := false
	cs := connect(t, root, func(context.Context, ...string) (string, error) { called = true; return "", nil })
	r := research(t, cs, ".env")
	assert.True(t, r.IsError)
	assert.False(t, called, "the merge must not read a secret file")
	assert.NotContains(t, errText(r), "Hunter2pw")
}

func TestResearchErrorDoesNotEchoFileText(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "bad.md"), []byte("hello\n"), 0o644))
	cs := connect(t, root, func(context.Context, ...string) (string, error) {
		return "", errors.New(`unknown section "hello": TOPSECRET`)
	})
	r := research(t, cs, "bad.md")
	assert.True(t, r.IsError)
	assert.NotContains(t, errText(r), "TOPSECRET")
	assert.NotContains(t, errText(r), "hello")
}
