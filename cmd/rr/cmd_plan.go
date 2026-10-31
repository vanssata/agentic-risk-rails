package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
)

func init() {
	cli.Register(func() *cobra.Command {
		c := &cobra.Command{Use: "plan", Short: "Implementation plan DAG"}
		var file string
		check := &cobra.Command{
			Use:   "check",
			Short: "Validate the plan (ids, cycles, file overlap needs after) and print its waves",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				raw, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				p, err := plan.Parse(raw)
				if err != nil {
					return err
				}
				waves, err := plan.Waves(p)
				if err != nil {
					return err
				}
				for i, w := range waves {
					ids := make([]string, len(w))
					for j, s := range w {
						ids[j] = s.ID
					}
					fmt.Fprintf(cmd.OutOrStdout(), "wave %d: %s\n", i+1, strings.Join(ids, " "))
				}
				return nil
			},
		}
		check.Flags().StringVar(&file, "file", "plan.yaml", "plan file")
		c.AddCommand(check)
		return c
	})
}
