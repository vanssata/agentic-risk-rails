package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
)

func init() {
	cli.Register(func() *cobra.Command {
		wd, _ := os.Getwd()
		var root string
		var files []string
		var budget int
		c := &cobra.Command{
			Use:   "recall --files a,b",
			Short: "What earlier tasks did to these files: facts, review findings, open risks, git log -S",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if len(files) == 0 || budget <= 0 {
					return errors.New("want --files and a positive --budget")
				}
				e, _, err := flowEnv(cmd.Context(), root)
				if err != nil {
					return err
				}
				out, err := e.Recall(cmd.Context(), files, budget)
				if err != nil {
					return err
				}
				_, err = fmt.Fprint(cmd.OutOrStdout(), out)
				return err
			},
		}
		c.Flags().StringVar(&root, "root", wd, "repository root")
		c.Flags().StringSliceVar(&files, "files", nil, "repo-relative paths")
		c.Flags().IntVar(&budget, "budget", 4000, "answer size in tokens")
		return c
	})
}
