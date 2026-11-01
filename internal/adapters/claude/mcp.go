package claude

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// mcpServer is the name `rr mcp` is registered under; its tools are mcp__rr__*
// and read-only (triage, research, status), so settings.json allows them.
// Format: docs/research/verified/claude-code.md (MCP).
const mcpServer = "rr"

type mcpDoc struct {
	MCPServers map[string]mcpEntry `json:"mcpServers"`
}

type mcpEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type mcpGen struct{}

func (mcpGen) Name() string { return "claude-mcp" }

func (mcpGen) Render(context.Context, core.SyncInput) ([]core.File, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	err := enc.Encode(mcpDoc{MCPServers: map[string]mcpEntry{mcpServer: {Command: "rr", Args: []string{"mcp"}}}})
	if err != nil {
		return nil, err
	}
	return []core.File{{Path: ".mcp.json", Content: buf.Bytes()}}, nil
}
