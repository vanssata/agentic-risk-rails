// Package mcp serves the read-only rr tools (triage, affected, research, status)
// over MCP. Each tool runs the matching rr subcommand through Runner, so the
// CLI stays the single implementation.
package mcp

import (
	"context"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Runner executes `rr <args...>` and returns its stdout.
type Runner func(ctx context.Context, args ...string) (string, error)

type triageIn struct {
	Files []string `json:"files" jsonschema:"repo-relative files the task touches"`
	Goal  string   `json:"goal,omitempty" jsonschema:"task goal"`
}

type affectedIn struct {
	Files []string `json:"files,omitempty" jsonschema:"changed files; default is the git changes"`
}

type researchIn struct {
	Reports []string `json:"reports" jsonschema:"scout report files to merge"`
}

type noIn struct{}

// NewServer registers the four tools; root is the repository they operate on.
func NewServer(root string, run Runner) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "rr", Version: "v4"}, nil)
	tool(s, "triage", "Score the six risk axes of a change and return its mode (read-only).", run,
		func(in triageIn) []string {
			a := []string{"triage", "--json", "--root", root, "--files", strings.Join(in.Files, ",")}
			if in.Goal != "" {
				a = append(a, "--goal", in.Goal)
			}
			return a
		})
	tool(s, "affected", "List the tests affected by changed files and whether a full run is required (read-only).", run,
		func(in affectedIn) []string { return append([]string{"affected", "--root", root}, in.Files...) })
	tool(s, "research", "Merge scout reports into one brief (read-only).", run,
		func(in researchIn) []string { return append([]string{"research", "merge"}, in.Reports...) })
	tool(s, "status", "Show the open task of this checkout as JSON (read-only).", run,
		func(noIn) []string { return []string{"status", "--json", "--root", root} })
	return s
}

func tool[In any](s *sdk.Server, name, desc string, run Runner, args func(In) []string) {
	sdk.AddTool(s, &sdk.Tool{Name: name, Description: desc},
		func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
			out, err := run(ctx, args(in)...)
			if err != nil {
				return nil, nil, err
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: out}}}, nil, nil
		})
}
