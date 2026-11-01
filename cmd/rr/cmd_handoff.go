package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/flow"
)

func init() {
	cli.Register(func() *cobra.Command {
		wd, _ := os.Getwd()
		var root, task string
		c := &cobra.Command{
			Use:   "handoff",
			Short: "Write .rr/run/<task>/handoff.md: the journal and the current diff, for the next session",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				e, _, err := flowEnv(cmd.Context(), root)
				if err != nil {
					return err
				}
				if task == "" {
					if task, err = flow.OpenTask(cmd.Context(), e.Journal); err != nil {
						return err
					}
				}
				p, err := e.Handoff(cmd.Context(), task)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), p)
				return nil
			},
		}
		c.Flags().StringVar(&root, "root", wd, "repository root")
		c.Flags().StringVar(&task, "task", "", "task id (default: the task in flight)")
		return c
	})
}
