package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/projection"
)

const statusRecent = 5

// taskFiles lists the .jsonl journal files in dir, sorted.
func taskFiles(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	sort.Strings(m)
	return m
}

func taskName(path string) string { return strings.TrimSuffix(filepath.Base(path), ".jsonl") }

func init() {
	cli.Register(func() *cobra.Command {
		var asJSON bool
		var root string
		c := &cobra.Command{
			Use:   "status",
			Short: "Show the open task of this checkout",
			RunE: func(cmd *cobra.Command, _ []string) error {
				out := cmd.OutOrStdout()
				files := taskFiles(journal.RunDir(root))
				if len(files) == 0 {
					if asJSON {
						fmt.Fprintln(out, "null")
					} else {
						fmt.Fprintln(out, "no open task")
					}
					return nil
				}
				events, err := journal.ReadFile(files[0])
				if err != nil {
					return err
				}
				st := projection.BuildStatus(events, statusRecent)
				if asJSON {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(st)
				}
				fmt.Fprintf(out, "task: %s\nmode: %s\nevents: %d\n", st.Task, st.Mode, st.Total)
				types := make([]string, 0, len(st.Counts))
				for t := range st.Counts {
					types = append(types, t)
				}
				sort.Strings(types)
				for _, t := range types {
					fmt.Fprintf(out, "  %s: %d\n", t, st.Counts[t])
				}
				fmt.Fprintln(out, "recent:")
				for _, e := range st.Recent {
					fmt.Fprintf(out, "  %s %s\n", e.Time.Format("15:04:05"), e.Type)
				}
				return nil
			},
		}
		wd, _ := os.Getwd()
		c.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
		c.Flags().StringVar(&root, "root", wd, "repository root")
		return c
	})
}
