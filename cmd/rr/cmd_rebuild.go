package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/projection"
)

func summaries(dir string) ([]projection.Summary, error) {
	out := []projection.Summary{}
	for _, p := range taskFiles(dir) {
		events, err := journal.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, projection.Summarize(events))
	}
	return out, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func init() {
	cli.Register(func() *cobra.Command {
		var root string
		c := &cobra.Command{
			Use:   "rebuild",
			Short: "Regenerate .rr/index.json and the state cache from journal files",
			RunE: func(cmd *cobra.Command, _ []string) error {
				closed, err := summaries(journal.TasksDir(root))
				if err != nil {
					return err
				}
				open, err := summaries(journal.RunDir(root))
				if err != nil {
					return err
				}
				if err := writeJSON(filepath.Join(root, ".rr", "index.json"), map[string]any{"tasks": closed}); err != nil {
					return err
				}
				if err := writeJSON(filepath.Join(journal.RunDir(root), "state.cache.json"), map[string]any{"open": open}); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "rebuilt: %d closed, %d open\n", len(closed), len(open))
				return nil
			},
		}
		wd, _ := os.Getwd()
		c.Flags().StringVar(&root, "root", wd, "repository root")
		return c
	})
}
