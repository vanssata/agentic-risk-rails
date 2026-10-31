package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/triage"
)

func init() {
	cli.Register(func() *cobra.Command {
		var (
			root, file, goal string
			files, declare   []string
			spec, asJSON     bool
			sessions         int
		)
		c := &cobra.Command{
			Use:   "triage --files a,b",
			Short: "Score the six risk axes of a change and print its mode (writes nothing)",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				pol := core.StrictDefaults() // a missing file is the strictest policy
				raw, err := os.ReadFile(filepath.Join(root, file))
				switch {
				case err == nil:
					if pol, err = policy.Load(raw); err != nil {
						return fmt.Errorf("%s: %w", file, err)
					}
				case !errors.Is(err, fs.ErrNotExist):
					return err
				}
				declared := map[core.Axis]int{}
				for _, d := range declare {
					k, v, ok := strings.Cut(d, "=")
					n, nerr := strconv.Atoi(v)
					var a core.Axis
					if !ok || nerr != nil || n < 0 || n > 2 || a.UnmarshalText([]byte(k)) != nil {
						return fmt.Errorf("--declare %q: want axis=0..2", d)
					}
					declared[core.Axis(k)] = n
				}
				tree, err := policy.ListFiles(cmd.Context(), root)
				if err != nil {
					return err
				}
				refs, content := triage.Load(root, files, tree, pol.Risk.Axes[core.AxisCoverage].TestGlobs)
				w := triage.Score(pol, triage.Input{Files: files, Goal: goal, Declared: declared, Refs: refs,
					Tree: tree, Content: content, Spec: spec, Sessions: sessions})
				out := cmd.OutOrStdout()
				if asJSON {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(w)
				}
				for _, r := range w.Reasons {
					fmt.Fprintln(out, r)
				}
				fmt.Fprintf(out, "W %d -> %s\n", w.Total(), w.Mode)
				return nil
			},
		}
		wd, _ := os.Getwd()
		c.Flags().StringVar(&root, "root", wd, "repository root")
		c.Flags().StringVar(&file, "file", "riskrails.yaml", "policy file, relative to --root")
		c.Flags().StringSliceVar(&files, "files", nil, "repo-relative files the task touches")
		c.Flags().StringVar(&goal, "goal", "", "task goal (scanned for behaviour keywords)")
		c.Flags().StringSliceVar(&declare, "declare", nil, "raise an axis: axis=0..2 (never lowers a measurement)")
		c.Flags().BoolVar(&spec, "spec", false, "a spec drives the task (programme trigger)")
		c.Flags().IntVar(&sessions, "sessions", 1, "sessions the task spans (programme trigger)")
		c.Flags().BoolVar(&asJSON, "json", false, "print JSON")
		_ = c.MarkFlagRequired("files")
		return c
	})
}
