package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func init() {
	cli.Register(func() *cobra.Command {
		var root string
		c := &cobra.Command{
			Use:   "doctor",
			Short: "Verify journal chains, task.md files and required events",
			RunE: func(cmd *cobra.Command, _ []string) error {
				out := cmd.OutOrStdout()
				var problems []string
				for _, p := range taskFiles(journal.RunDir(root)) {
					if err := journal.Verify(p); err != nil {
						problems = append(problems, err.Error())
					}
				}
				for _, p := range taskFiles(journal.TasksDir(root)) {
					if err := journal.Verify(p); err != nil {
						problems = append(problems, err.Error())
					}
					task := taskName(p)
					if _, err := os.Stat(filepath.Join(journal.TasksDir(root), task, "task.md")); err != nil {
						problems = append(problems, fmt.Sprintf("%s: task.md missing", task))
					}
					events, err := journal.ReadFile(p)
					if err != nil {
						problems = append(problems, err.Error())
						continue
					}
					seen := map[string]bool{}
					for _, e := range events {
						seen[e.Type] = true
					}
					for _, t := range journal.Required() {
						if !seen[t] {
							problems = append(problems, fmt.Sprintf("%s: required event %s missing", task, t))
						}
					}
				}
				for _, p := range problems {
					fmt.Fprintln(out, "problem:", p)
				}
				if len(problems) > 0 {
					return ExitError{Code: 1}
				}
				fmt.Fprintln(out, "ok")
				return nil
			},
		}
		wd, _ := os.Getwd()
		c.Flags().StringVar(&root, "root", wd, "repository root")
		return c
	})
}
