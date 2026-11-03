package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
)

var validCostTask = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func init() {
	cli.Register(func() *cobra.Command {
		var task, root string
		var asJSON bool
		c := &cobra.Command{
			Use:   "cost",
			Short: "Token usage and list-price cost of a task, from runtime transcripts",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if !validCostTask.MatchString(task) || strings.Contains(task, "..") {
					return fmt.Errorf("invalid --task %q", task)
				}
				path := filepath.Join(journal.RunDir(root), task+".jsonl")
				if _, err := os.Stat(path); err != nil {
					path = filepath.Join(journal.TasksDir(root), task+".jsonl")
				}
				events, err := journal.ReadFile(path)
				if err != nil {
					return err
				}
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				absRoot, err := filepath.Abs(root)
				if err != nil {
					return err
				}
				items, err := ledger.Collect(events, ledger.TranscriptRoots(home, absRoot))
				if err != nil {
					return err
				}
				prices, err := ledger.DefaultPrices()
				if err != nil {
					return err
				}
				out := cmd.OutOrStdout()
				dims := []string{"phase", "tier", "model"}
				res := map[string][]ledger.Row{}
				for _, d := range dims {
					res[d] = ledger.Group(items, prices, d)
				}
				if asJSON {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(res)
				}
				for _, d := range dims {
					fmt.Fprintf(out, "by %s:\n", d)
					for _, r := range res[d] {
						note := ""
						if r.Unpriced > 0 {
							note = fmt.Sprintf("  (%d unpriced or unknown: total incomplete)", r.Unpriced)
						}
						fmt.Fprintf(out, "  %-20s in=%d out=%d cache_read=%d cache_write=%d  $%.4f%s\n",
							r.Key, r.Input, r.Output, r.CacheRead, r.CacheWrite, r.USD, note)
					}
				}
				return nil
			},
		}
		c.Flags().StringVar(&task, "task", "", "task id")
		_ = c.MarkFlagRequired("task")
		c.Flags().StringVar(&root, "root", ".", "repository root")
		c.Flags().BoolVar(&asJSON, "json", false, "JSON output")
		return c
	})
}
