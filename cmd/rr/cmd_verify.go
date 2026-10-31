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
	root string
}

func (f *verifyFlags) bind(c *cobra.Command) {
	wd, _ := os.Getwd()
	c.PersistentFlags().StringVar(&f.root, "root", wd, "repository root")
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

func printJSON(c *cobra.Command, v any) error {
	enc := json.NewEncoder(c.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// taskTrust loads the task's journal and the trust inputs recorded in task_started.
func taskTrust(ctx context.Context, root, task string) ([]core.Event, verify.Trust, error) {
	events, err := journal.New(root).Events(ctx, task)
	if err != nil {
		return nil, verify.Trust{}, err
	}
	t, err := verify.LoadTrust(root, task, events)
	return events, t, err
}

func init() {
	cli.Register(func() *cobra.Command {
		var f verifyFlags
		var task string
		var closing bool
		c := &cobra.Command{
			Use:   "verify",
			Short: "Run the tests for the task's changes (affected, or full when policy requires)",
			RunE: func(cmd *cobra.Command, _ []string) error {
				spec, err := f.spec(cmd.Context())
				if err != nil {
					return err
				}
				events, trust, err := taskTrust(cmd.Context(), f.root, task)
				if err != nil {
					return err
				}
				mode, err := verify.TaskMode(events)
				if err != nil {
					return err
				}
				changed, err := verify.TaskChanged(cmd.Context(), f.root, trust, false)
				if err != nil {
					return err
				}
				rep, err := verify.Run(cmd.Context(), verify.Input{
					Root: f.root, Task: task, Changed: changed, Spec: spec, Mode: mode, Closing: closing,
					Tree:    func(ctx context.Context, ign bool) (string, error) { return verify.TreeFingerprint(ctx, f.root, ign) },
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

		// facts takes every trust input (scope, base_sha, baseline) from the task journal only.
		facts := &cobra.Command{
			Use:   "facts",
			Short: "Check the two close facts: green full verify on this tree, changes inside scope",
			RunE: func(cmd *cobra.Command, _ []string) error {
				events, trust, err := taskTrust(cmd.Context(), f.root, task)
				if err != nil {
					return err
				}
				changed, err := verify.TaskChanged(cmd.Context(), f.root, trust, true)
				if err != nil {
					return err
				}
				tree, err := verify.TreeFingerprint(cmd.Context(), f.root, true)
				if err != nil {
					return err
				}
				fc := verify.ComputeFacts(events, tree, changed, trust.Scope)
				if err := printJSON(cmd, fc); err != nil {
					return err
				}
				if !fc.Ok() {
					return errors.New("close facts do not hold")
				}
				return nil
			},
		}
		c.AddCommand(facts)
		return c
	})
}
