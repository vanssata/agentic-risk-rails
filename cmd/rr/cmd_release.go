package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/release"
)

// releaseAdapter picks the named adapter, or the single detected one.
func releaseAdapter(root, eco string) (core.ReleaseAdapter, error) {
	if eco != "" {
		if a, ok := release.Get(eco); ok {
			return a, nil
		}
		return nil, fmt.Errorf("unknown ecosystem %q", eco)
	}
	d := release.Detected(root)
	if len(d) != 1 {
		return nil, fmt.Errorf("found %d release ecosystems in %s; pass --ecosystem", len(d), root)
	}
	return d[0], nil
}

func init() {
	cli.Register(func() *cobra.Command {
		var root, eco string
		c := &cobra.Command{Use: "release", Short: "Release preflight, dry-run, tag preparation (never publishes: CI does)"}
		wd, _ := os.Getwd()
		c.PersistentFlags().StringVar(&root, "root", wd, "repository root")
		c.PersistentFlags().StringVar(&eco, "ecosystem", "", "composer|npm|pypi|docker (default: detected)")
		c.AddCommand(
			&cobra.Command{Use: "preflight", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
				a, err := releaseAdapter(root, eco)
				if err != nil {
					return err
				}
				bad := 0
				for _, ch := range a.Preflight(cmd.Context(), root) {
					if !ch.OK {
						bad++
					}
					if err := printJSON(cmd, ch); err != nil {
						return err
					}
				}
				if bad > 0 {
					return fmt.Errorf("release preflight: %d check(s) failed", bad)
				}
				return nil
			}},
			&cobra.Command{Use: "dry-run", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
				a, err := releaseAdapter(root, eco)
				if err != nil {
					return err
				}
				ch, err := a.DryRun(cmd.Context(), root)
				if err != nil {
					return err
				}
				if err := printJSON(cmd, ch); err != nil {
					return err
				}
				if !ch.OK {
					return fmt.Errorf("release dry-run failed")
				}
				return nil
			}},
			&cobra.Command{Use: "prepare <version>", Short: "bump the version file (if the ecosystem has one); the tag is made by a human", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
				a, err := releaseAdapter(root, eco)
				if err != nil {
					return err
				}
				files, err := a.PrepareTag(cmd.Context(), root, args[0])
				if err != nil {
					return err
				}
				for _, f := range files {
					if err := os.WriteFile(filepath.Join(root, f.Path), f.Content, 0o644); err != nil {
						return err
					}
					fmt.Fprintln(cmd.OutOrStdout(), "updated", f.Path)
				}
				return nil
			}},
			&cobra.Command{Use: "workflow", Short: "write .github/workflows/rr-release-<ecosystem>.yml", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
				a, err := releaseAdapter(root, eco)
				if err != nil {
					return err
				}
				f := a.CIWorkflow()
				p := filepath.Join(root, f.Path)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(p, f.Content, 0o644); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "wrote", f.Path)
				return nil
			}},
		)
		return c
	})
	cli.Register(func() *cobra.Command {
		var root, version string
		var check bool
		wd, _ := os.Getwd()
		c := &cobra.Command{Use: "changelog", Short: "Changelog checks", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if !check {
				return fmt.Errorf("nothing to do: pass --check")
			}
			if err := release.CheckChangelog(root, version); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "changelog ok")
			return nil
		}}
		c.Flags().StringVar(&root, "root", wd, "repository root")
		c.Flags().StringVar(&version, "version", "", "version section to require (default Unreleased)")
		c.Flags().BoolVar(&check, "check", false, "fail unless the section is present and non-empty")
		return c
	})
}
