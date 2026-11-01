package main

import (
	"bytes"
	"context"
	"os"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/mcp"
)

// runSelf runs an rr subcommand in-process and returns its stdout.
// A failing command returns its output (stderr merged) inside the error.
func runSelf(ctx context.Context, args ...string) (string, error) {
	var out bytes.Buffer
	c := cli.Root(version)
	c.SetArgs(args)
	c.SetOut(&out)
	c.SetErr(&out)
	err := c.ExecuteContext(ctx)
	return out.String(), err
}

func init() {
	cli.Register(func() *cobra.Command {
		var root string
		c := &cobra.Command{
			Use:   "mcp",
			Short: "Serve triage, research and status as read-only MCP tools over stdio",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return mcp.NewServer(root, runSelf).Run(cmd.Context(), &sdk.StdioTransport{})
			},
		}
		wd, _ := os.Getwd()
		c.Flags().StringVar(&root, "root", wd, "repository root")
		return c
	})
}
