package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// verifyFlags are shared by `rr verify` and `rr affected`.
type verifyFlags struct {
	root, base, mode string
}

func (f *verifyFlags) bind(c *cobra.Command) {
	wd, _ := os.Getwd()
	c.Flags().StringVar(&f.root, "root", wd, "repository root")
	c.Flags().StringVar(&f.base, "base", "", "ref to diff against (default HEAD, plus untracked files)")
	c.Flags().StringVar(&f.mode, "mode", string(core.ModeGuarded), "task mode (light|guarded|full|full_irreversible|programme)")
}

func (f *verifyFlags) spec() (core.VerifySpec, error) {
	raw, err := os.ReadFile(filepath.Join(f.root, "riskrails.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return core.StrictDefaults().Verify, nil
	}
	if err != nil {
		return core.VerifySpec{}, err
	}
	p, err := policy.Load(raw)
	if err != nil {
		return core.VerifySpec{}, fmt.Errorf("riskrails.yaml: %w", err)
	}
	return p.Verify, nil
}

func (f *verifyFlags) mod() (core.Mode, error) {
	m := core.Mode(f.mode)
	if m.Rank() < 0 {
		return "", fmt.Errorf("unknown mode %q", f.mode)
	}
	return m, nil
}

func printJSON(c *cobra.Command, v any) error {
	enc := json.NewEncoder(c.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func init() {
	cli.Register(func() *cobra.Command {
		var f verifyFlags
		var task string
		var closing bool
		c := &cobra.Command{
			Use:   "verify",
			Short: "Run the tests for the current changes (affected, or full when policy requires)",
			RunE: func(cmd *cobra.Command, _ []string) error {
				spec, err := f.spec()
				if err != nil {
					return err
				}
				mode, err := f.mod()
				if err != nil {
					return err
				}
				changed, err := verify.ChangedFiles(cmd.Context(), f.root, f.base)
				if err != nil {
					return err
				}
				tree, err := verify.TreeFingerprint(cmd.Context(), f.root)
				if err != nil {
					return err
				}
				rep, err := verify.Run(cmd.Context(), verify.Input{
					Root: f.root, Task: task, Changed: changed, Spec: spec, Mode: mode,
					Closing: closing, Tree: tree, Journal: journal.New(f.root),
				})
				if err != nil {
					return err
				}
				if err := printJSON(cmd, rep); err != nil {
					return err
				}
				if !rep.Passed {
					return errors.New("verify failed")
				}
				return nil
			},
		}
		f.bind(c)
		c.Flags().StringVar(&task, "task", "", "task id (journal)")
		c.Flags().BoolVar(&closing, "close", false, "closing run: always full")
		_ = c.MarkFlagRequired("task")

		var scope []string
		facts := &cobra.Command{
			Use:   "facts",
			Short: "Check the two close facts: green full verify on this tree, changes inside scope",
			RunE: func(cmd *cobra.Command, _ []string) error {
				events, err := journal.New(f.root).Events(cmd.Context(), task)
				if err != nil {
					return err
				}
				changed, err := verify.ChangedFiles(cmd.Context(), f.root, f.base)
				if err != nil {
					return err
				}
				tree, err := verify.TreeFingerprint(cmd.Context(), f.root)
				if err != nil {
					return err
				}
				fc := verify.ComputeFacts(events, tree, changed, scope)
				if err := printJSON(cmd, fc); err != nil {
					return err
				}
				if !fc.Ok() {
					return errors.New("close facts do not hold")
				}
				return nil
			},
		}
		facts.Flags().StringSliceVar(&scope, "scope", nil, "globs the task may change")
		c.AddCommand(facts)
		return c
	})
}
