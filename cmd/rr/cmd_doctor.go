package main

import (
	"encoding/json"
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
		var repair bool
		c := &cobra.Command{
			Use:   "doctor",
			Short: "Verify journal chains, task.md files and required events",
			RunE: func(cmd *cobra.Command, _ []string) error {
				out := cmd.OutOrStdout()
				var problems []string
				for _, p := range taskFiles(journal.RunDir(root)) {
					if repair {
						removed, err := journal.Repair(root, p)
						if err != nil {
							problems = append(problems, err.Error())
						} else if removed != nil {
							fmt.Fprintf(out, "repaired: %s: removed %d bytes (saved as %s.torn.*)\n", p, len(removed), p)
						}
					}
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
					want, err := journal.ReadHead(root, task)
					got, gerr := journal.HeadHash(p)
					if err != nil || gerr != nil || want != got {
						problems = append(problems, fmt.Sprintf("%s: head hash does not match the anchor in task.md (edited or truncated after close)", task))
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
				problems = append(problems, orphanProblems(root)...)
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
		c.Flags().BoolVar(&repair, "repair", false, "truncate a trailing partial (non-JSON) line of open tasks")
		c.Flags().StringVar(&root, "root", wd, "repository root")
		return c
	})
}

// orphanProblems finds task.md files without a journal and index.json entries whose files are gone.
func orphanProblems(root string) []string {
	var out []string
	dirs, _ := filepath.Glob(filepath.Join(journal.TasksDir(root), "*", "task.md"))
	for _, md := range dirs {
		task := filepath.Base(filepath.Dir(md))
		if _, err := os.Stat(filepath.Join(journal.TasksDir(root), task+".jsonl")); err != nil {
			out = append(out, fmt.Sprintf("%s: task.md without journal", task))
		}
	}
	b, err := os.ReadFile(filepath.Join(root, ".rr", "index.json"))
	if err != nil {
		return out
	}
	var idx struct {
		Tasks []struct {
			Task string `json:"task"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return append(out, "index.json: "+err.Error())
	}
	for _, t := range idx.Tasks {
		for _, f := range []string{t.Task + ".jsonl", filepath.Join(t.Task, "task.md")} {
			if _, err := os.Stat(filepath.Join(journal.TasksDir(root), f)); err != nil {
				out = append(out, fmt.Sprintf("%s: listed in index.json but %s is missing", t.Task, f))
			}
		}
	}
	return out
}
