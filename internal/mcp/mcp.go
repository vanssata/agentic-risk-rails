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

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/guard"
	"github.com/vanssata/agentic-risk-rails/internal/wiring"
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

// NewServer registers the three tools (triage, research, status); root is the repository they operate on.
func NewServer(root string, run Runner) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "rr", Version: "v4"}, nil)
	tool(s, "triage", "Score the six risk axes of a change and return its mode (read-only).", run,
		func(_ context.Context, in triageIn) ([]string, error) {
			if err := relPaths(in.Files); err != nil {
				return nil, err
			}
			a := []string{"triage", "--json", "--root", root, "--files", strings.Join(in.Files, ",")}
			if in.Goal != "" {
				a = append(a, "--goal="+in.Goal)
			}
			return a, nil
		}, false)
	// No "affected" tool: mapping runs the project's test tooling (jest config,
	// node_modules/.bin) and the MCP server runs outside the sandbox (errata #38).
	tool(s, "research", "Merge scout reports into one brief (read-only).", run,
		func(ctx context.Context, in researchIn) ([]string, error) {
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
				if err := readAllowed(ctx, root, p); err != nil {
					return nil, fmt.Errorf("report %q refused: %w", r, err)
				}
				a = append(a, p)
			}
			return a, nil
		}, true)
	tool(s, "status", "Show the open task of this checkout as JSON (read-only).", run,
		func(context.Context, noIn) ([]string, error) {
			return []string{"status", "--json", "--root", root}, nil
		}, false)
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

// readAllowed asks the guard whether the agent may read abs: secret_reads and
// sandbox.no_read match, and any guard or context error, refuse (fail-closed).
// The MCP server runs outside the runtime sandbox, so this is the only check.
func readAllowed(ctx context.Context, root, abs string) error {
	gc, err := wiring.GuardContext(ctx, root, "")
	if err != nil {
		return fmt.Errorf("cannot build guard context")
	}
	v := guard.New().Check(ctx, core.ToolCall{Tool: "Read", Event: "PreToolUse", Paths: []string{abs}, Cwd: gc.Root}, gc)
	if v.Decision != core.Allow {
		return fmt.Errorf("read denied by policy (%s)", v.Rule)
	}
	return nil
}

// tool registers one tool. quiet withholds the command output from errors: a
// failing merge echoes file text, which may be a secret.
func tool[In any](s *sdk.Server, name, desc string, run Runner, args func(context.Context, In) ([]string, error), quiet bool) {
	sdk.AddTool(s, &sdk.Tool{Name: name, Description: desc},
		func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, any, error) {
			a, err := args(ctx, in)
			if err != nil {
				return nil, nil, err
			}
			out, err := run(ctx, a...)
			if err != nil {
				if quiet {
					return nil, nil, fmt.Errorf("rr %s failed (output withheld)", name)
				}
				return nil, nil, err
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: out}}}, nil, nil
		})
}
