package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// verifyFlags are shared by `rr verify` (and its subcommands) and `rr affected`.
type verifyFlags struct {
	root, base, mode string
}

func (f *verifyFlags) bind(c *cobra.Command) {
	wd, _ := os.Getwd()
	c.PersistentFlags().StringVar(&f.root, "root", wd, "repository root")
	c.PersistentFlags().StringVar(&f.base, "base", "", "ref to diff against (default HEAD, plus untracked files)")
	c.PersistentFlags().StringVar(&f.mode, "mode", string(core.ModeGuarded), "task mode (light|guarded|full|full_irreversible|programme)")
}

// spec is the verify section of the RESOLVED policy (strictest of in-force and
// working tree, clamped by the ceiling). Any resolve error refuses: no fallback.
func (f *verifyFlags) spec(ctx context.Context) (core.VerifySpec, error) {
	r, err := resolve(ctx, f.root)
	if err != nil {
		return core.VerifySpec{}, fmt.Errorf("refusing: policy not resolved: %w", err)
	}
	return r.eff.Policy.Verify, nil
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

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull) // /dev/null is a character device too
	return err != nil || !os.SameFile(fi, null)
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
				spec, err := f.spec(cmd.Context())
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
				rep, err := verify.Run(cmd.Context(), verify.Input{
					Root: f.root, Task: task, Changed: changed, Spec: spec, Mode: mode, Closing: closing,
					Tree:    func(ctx context.Context) (string, error) { return verify.TreeFingerprint(ctx, f.root) },
					Journal: journal.New(f.root),
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
		c.PersistentFlags().StringVar(&task, "task", "", "task id (journal)")
		c.Flags().BoolVar(&closing, "close", false, "closing run: always full")
		_ = c.MarkPersistentFlagRequired("task")

		var scope []string
		facts := &cobra.Command{
			Use:   "facts",
			Short: "Check the two close facts: green full verify on this tree, changes inside scope",
			RunE: func(cmd *cobra.Command, _ []string) error {
				events, err := journal.New(f.root).Events(cmd.Context(), task)
				if err != nil {
					return err
				}
				// The task's scope comes from its journal. --scope is a fallback for a human at a
				// terminal only: an agent's Bash tool has no TTY, so it cannot widen its own scope.
				if js := verify.ScopeFromEvents(events); js != nil {
					if len(scope) > 0 {
						return errors.New("refusing: the task journal already carries a scope; --scope is not accepted")
					}
					scope = js
				} else if len(scope) == 0 || !isTerminal(os.Stdin) {
					return errors.New("refusing: no scope in the task journal, and --scope needs an interactive terminal")
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
		facts.Flags().StringSliceVar(&scope, "scope", nil, "globs the task may change (human terminal only)")
		c.AddCommand(facts)
		return c
	})
}
