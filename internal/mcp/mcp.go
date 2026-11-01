// Package mcp serves the read-only rr tools (triage, research, status)
// over MCP. Each tool runs the matching rr subcommand through Runner, so the
// CLI stays the single implementation.
package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Runner executes `rr <args...>` and returns its stdout.
type Runner func(ctx context.Context, args ...string) (string, error)

type triageIn struct {
	Files []string `json:"files" jsonschema:"repo-relative files the task touches"`
	Goal  string   `json:"goal,omitempty" jsonschema:"task goal"`
}

type researchIn struct {
	Reports []string `json:"reports" jsonschema:"scout report files to merge"`
}

type noIn struct{}

// NewServer registers the four tools; root is the repository they operate on.
func NewServer(root string, run Runner) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "rr", Version: "v4"}, nil)
	tool(s, "triage", "Score the six risk axes of a change and return its mode (read-only).", run,
		func(in triageIn) ([]string, error) {
			if err := relPaths(in.Files); err != nil {
				return nil, err
			}
			a := []string{"triage", "--json", "--root", root, "--files", strings.Join(in.Files, ",")}
			if in.Goal != "" {
				a = append(a, "--goal="+in.Goal)
			}
			return a, nil
		})
	// No "affected" tool: mapping runs the project's test tooling (jest config,
	// node_modules/.bin) and the MCP server runs outside the sandbox (errata #38).
	tool(s, "research", "Merge scout reports into one brief (read-only).", run,
		func(in researchIn) ([]string, error) {
			if err := relPaths(in.Reports); err != nil {
				return nil, err
			}
			a := []string{"research", "merge", "--"}
			for _, r := range in.Reports {
				p, err := filepath.EvalSymlinks(filepath.Join(root, r))
				if err != nil {
					return nil, err
				}
				if realRoot, err := filepath.EvalSymlinks(root); err != nil {
					return nil, err
				} else if rel, err := filepath.Rel(realRoot, p); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return nil, fmt.Errorf("%q resolves outside the repository", r)
				}
				a = append(a, p)
			}
			return a, nil
		})
	tool(s, "status", "Show the open task of this checkout as JSON (read-only).", run,
		func(noIn) ([]string, error) { return []string{"status", "--json", "--root", root}, nil })
	return s
}

// relPaths rejects entries that could act as flags or leave the repository.
func relPaths(ps []string) error {
	for _, p := range ps {
		if p == "" || strings.HasPrefix(p, "-") || filepath.IsAbs(p) || strings.Contains(p, "..") {
			return fmt.Errorf("invalid path %q: must be repo-relative, no leading '-' and no '..'", p)
		}
	}
	return nil
}

func tool[In any](s *sdk.Server, name, desc string, run Runner, args func(In) ([]string, error)) {
	sdk.AddTool(s, &sdk.Tool{Name: name, Description: desc},
		func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
			a, err := args(in)
			if err != nil {
				return nil, nil, err
			}
			out, err := run(ctx, a...)
			if err != nil {
				return nil, nil, err
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: out}}}, nil, nil
		})
}
