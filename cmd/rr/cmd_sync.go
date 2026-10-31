package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
)

func init() {
	cli.Register(func() *cobra.Command {
		var check bool
		var root string
		c := &cobra.Command{
			Use:   "sync",
			Short: "Render runtime manifests from policy and effective tiers",
			RunE: func(cmd *cobra.Command, _ []string) error {
				in, err := rrsync.InputProvider(cmd.Context(), root)
				if err != nil {
					return err
				}
				files, err := rrsync.Render(cmd.Context(), in, rrsync.Generators())
				if err != nil {
					return err
				}
				if !check {
					if err := rrsync.Write(root, files); err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "wrote %d files\n", len(files))
					return nil
				}
				drift, err := rrsync.Drift(root, files)
				if err != nil {
					return err
				}
				for _, p := range drift {
					fmt.Fprintln(cmd.OutOrStdout(), "drift:", p)
				}
				if len(drift) > 0 {
					return ExitError{Code: 1}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "ok: %d files, %d generators\n", len(files), len(rrsync.Generators()))
				return nil
			},
		}
		wd, _ := os.Getwd()
		c.Flags().BoolVar(&check, "check", false, "fail if generated files differ from disk")
		c.Flags().StringVar(&root, "root", wd, "repository root")
		return c
	})
}
