package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/research"
)

func init() {
	cli.Register(func() *cobra.Command {
		c := &cobra.Command{Use: "research", Short: "Research factory: merge scout reports"}
		c.AddCommand(&cobra.Command{
			Use:   "merge <report-file>...",
			Short: "Merge scout reports (DES §5.4 schema) into a brief of at most 3k tokens",
			Args:  cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				var reports []research.Report
				for _, p := range args {
					b, err := os.ReadFile(p)
					if err != nil {
						return err
					}
					r, err := research.Parse(string(b))
					if err != nil {
						return fmt.Errorf("%s: %w", p, err)
					}
					reports = append(reports, r)
				}
				_, err := fmt.Fprint(cmd.OutOrStdout(), research.MergeBrief(research.Merge(reports), research.MaxBriefTokens))
				return err
			},
		})
		return c
	})
}
