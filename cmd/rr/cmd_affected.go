package main

import (
	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// The adapter flags are what riskrails.yaml writes in `affected: "rr affected --phpunit"`.
var affectedAdapters = []string{"phpunit", "jest", "vitest", "pytest", "go"}

func init() {
	cli.Register(func() *cobra.Command {
		var f verifyFlags
		var task string
		picked := map[string]*bool{}
		c := &cobra.Command{
			Use:   "affected [files...]",
			Short: "Print the tests affected by the changed files (default: git changes) and whether a full run is required",
			RunE: func(cmd *cobra.Command, files []string) error {
				spec, err := f.spec(cmd.Context())
				if err != nil {
					return err
				}
				mode := core.ModeGuarded // a preview without a task; with --task the journal's mode applies
				if task != "" {
					events, err := journal.New(f.root).Events(cmd.Context(), task)
					if err != nil {
						return err
					}
					if mode, err = verify.TaskMode(events); err != nil {
						return err
					}
				}
				var only []core.VerifyAdapterSpec
				for _, a := range spec.Adapters {
					if p, ok := picked[a.Name]; ok && *p {
						only = append(only, a)
					}
				}
				if len(only) > 0 {
					spec.Adapters = only
				}
				if len(files) == 0 {
					if files, err = verify.GitChanged(cmd.Context(), f.root); err != nil {
						return err
					}
				}
				sel, err := verify.Select(cmd.Context(), verify.Input{Root: f.root, Changed: files, Spec: spec, Mode: mode})
				if err != nil {
					return err
				}
				out := struct {
					Full      bool                `json:"full"`
					Reason    string              `json:"reason,omitempty"`
					Uncovered []string            `json:"uncovered,omitempty"`
					Tests     map[string][]string `json:"tests"`
				}{sel.Full, sel.Reason, sel.Uncovered, map[string][]string{}}
				for _, it := range sel.Items {
					out.Tests[it.Spec.Name] = it.Tests
				}
				return printJSON(cmd, out)
			},
		}
		f.bind(c)
		c.Flags().StringVar(&task, "task", "", "task id: use the mode recorded in its journal (default: guarded)")
		for _, n := range affectedAdapters {
			picked[n] = c.Flags().Bool(n, false, "only the "+n+" adapter")
		}
		return c
	})
}
