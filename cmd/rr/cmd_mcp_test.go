package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/mcp"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func text(t *testing.T, r *sdk.CallToolResult) string {
	t.Helper()
	require.NotEmpty(t, r.Content)
	return r.Content[0].(*sdk.TextContent).Text
}

func TestMCPContract(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")
	ctx := context.Background()
	st, ct := sdk.NewInMemoryTransports()
	ss, err := mcp.NewServer(root, runSelf).Connect(ctx, st, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cs.Close() })

	lt, err := cs.ListTools(ctx, nil)
	require.NoError(t, err)
	var names []string
	for _, tl := range lt.Tools {
		names = append(names, tl.Name)
	}
	assert.ElementsMatch(t, []string{"triage", "affected", "research", "status"}, names)

	r, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "triage", Arguments: map[string]any{"files": []string{"src/Controller/HomeController.php"}}})
	require.NoError(t, err)
	require.False(t, r.IsError, text(t, r))
	var w struct {
		Mode string `json:"mode"`
	}
	require.NoError(t, json.Unmarshal([]byte(text(t, r)), &w))
	assert.NotEmpty(t, w.Mode)

	r, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "status", Arguments: map[string]any{}})
	require.NoError(t, err)
	require.False(t, r.IsError, text(t, r))
	assert.Equal(t, "null", strings.TrimSpace(text(t, r)))

	r, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "research", Arguments: map[string]any{"reports": []string{"/nonexistent"}}})
	require.NoError(t, err)
	assert.True(t, r.IsError, "a failing command is a tool error, not a transport error")
}
