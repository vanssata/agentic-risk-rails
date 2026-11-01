package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/simplify"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

func init() {
	cli.Register(func() *cobra.Command {
		var root string
		c := &cobra.Command{
			Use:   "simplify [files...]",
			Short: "Deterministic simplify preflight (jscpd, ast-grep) as JSON for the rr-simplify skill",
			RunE: func(cmd *cobra.Command, files []string) error {
				if len(files) == 0 {
					var err error
					if files, err = verify.GitChanged(cmd.Context(), root); err != nil {
						return err
					}
				}
				return printJSON(cmd, simplify.Run(cmd.Context(), root, files))
			},
		}
		wd, _ := os.Getwd()
		c.Flags().StringVar(&root, "root", wd, "repository root")
		return c
	})
}
