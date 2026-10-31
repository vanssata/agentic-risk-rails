package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

type policyFlags struct {
	base, file, root string
	json             bool
}

func (f *policyFlags) bind(c *cobra.Command) {
	wd, _ := os.Getwd()
	c.Flags().StringVar(&f.base, "base", "", "git ref holding the policy in force (e.g. origin/main)")
	c.Flags().StringVar(&f.file, "file", "riskrails.yaml", "candidate policy file, relative to --root")
	c.Flags().StringVar(&f.root, "root", wd, "repository root")
	c.Flags().BoolVar(&f.json, "json", false, "print JSON")
	_ = c.MarkFlagRequired("base")
}

// compare diffs the working-tree policy file against the policy at --base.
func (f *policyFlags) compare(ctx context.Context) (core.Direction, []core.FieldChange, error) {
	base, err := policy.ReadAtRef(ctx, f.root, f.base)
	if err != nil {
		return core.Loosen, nil, err
	}
	cand := core.StrictDefaults() // a missing file is the strictest policy
	raw, err := os.ReadFile(filepath.Join(f.root, f.file))
	switch {
	case err == nil:
		if cand, err = policy.Load(raw); err != nil {
			return core.Loosen, nil, fmt.Errorf("%s: %w", f.file, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return core.Loosen, nil, err
	}
	files, err := policy.ListFiles(ctx, f.root)
	if err != nil {
		return core.Loosen, nil, err
	}
	return policy.Diff(base.Policy, cand, files)
}

func (f *policyFlags) print(w io.Writer, d core.Direction, changes []core.FieldChange) error {
	if changes == nil {
		changes = []core.FieldChange{}
	}
	if f.json {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Direction core.Direction     `json:"direction"`
			Changes   []core.FieldChange `json:"changes"`
		}{d, changes})
	}
	fmt.Fprintln(w, d)
	for _, ch := range changes {
		fmt.Fprintf(w, "  %-8s %s", ch.Direction, ch.Path)
		if ch.Detail != "" {
			fmt.Fprintf(w, "  %s", ch.Detail)
		}
		fmt.Fprintln(w)
	}
	return nil
}

func init() {
	cli.Register(func() *cobra.Command {
		root := &cobra.Command{Use: "policy", Short: "Compare riskrails.yaml against the policy in force"}

		var df policyFlags
		diff := &cobra.Command{
			Use:   "diff --base <ref>",
			Short: "Print TIGHTEN/LOOSEN and the changed fields versus the base ref",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				d, changes, err := df.compare(cmd.Context())
				if err != nil {
					return err
				}
				return df.print(cmd.OutOrStdout(), d, changes)
			},
		}
		df.bind(diff)

		var cf policyFlags
		check := &cobra.Command{
			Use:   "check --base <ref>",
			Short: "Exit 1 when the working-tree policy loosens the base (MIXED counts as loosening)",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				d, changes, err := cf.compare(cmd.Context())
				if err != nil {
					return err // an unverifiable policy is not ok: main exits 1
				}
				if err := cf.print(cmd.OutOrStdout(), d, changes); err != nil {
					return err
				}
				if d.Loosens() {
					return ExitError{Code: 1}
				}
				return nil
			},
		}
		cf.bind(check)

		root.AddCommand(diff, check)
		return root
	})
}
