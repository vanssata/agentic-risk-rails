package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/models"
)

var apiKeyEnv = map[string]string{
	models.Anthropic: "ANTHROPIC_API_KEY", models.OpenAI: "OPENAI_API_KEY", models.OpenRouter: "OPENROUTER_API_KEY",
}

var apiBase = map[string]string{
	models.Anthropic: "https://api.anthropic.com", models.OpenAI: "https://api.openai.com", models.OpenRouter: "https://openrouter.ai",
}

func init() {
	cli.Register(func() *cobra.Command {
		root := &cobra.Command{Use: "models", Short: "Model availability: probe and show effective tiers"}
		root.AddCommand(modelsProbe(), modelsShow())
		return root
	})
}

func modelsInput(cmd *cobra.Command, dir, runtime string) (models.Input, error) {
	r, err := resolve(cmd.Context(), dir)
	if err != nil {
		return models.Input{}, err
	}
	spec := r.eff.Policy.Models
	return models.Input{
		Spec: spec, Runtime: runtime, Account: models.LocalAccount,
		Cache: models.Cache{Path: models.ExpandPath(spec.Probe.Cache, r.home)}, Now: time.Now(),
	}, nil
}

func modelsProbe() *cobra.Command {
	var runtime, via, dir string
	var exclude []string
	c := &cobra.Command{
		Use:   "probe",
		Short: "Probe the candidates of a runtime and refresh the cache (costs tokens)",
		Long: "--via cli runs `<runtime> -p ok --model <m>` (~100 tokens per model); profile trusts the install " +
			"profile (every candidate PASS except --exclude); anthropic|openai|openrouter send one max_tokens:1 " +
			"request per candidate using ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := modelsInput(cmd, dir, runtime)
			if err != nil {
				return err
			}
			switch via {
			case "cli":
				in.Prober = models.CLIProber{Name: runtime, Bin: runtime}
			case "profile":
				in.Prober = models.ProfileProber{Name: runtime, Exclude: exclude}
			case models.Anthropic, models.OpenAI, models.OpenRouter:
				key := os.Getenv(apiKeyEnv[via])
				if key == "" {
					return fmt.Errorf("%s is not set", apiKeyEnv[via])
				}
				in.Prober = models.HTTPProber{Kind: via, BaseURL: apiBase[via], Key: key}
				in.Account = models.AccountHash(via, key)
			default:
				return fmt.Errorf("unknown --via %q", via)
			}
			in.Refresh = true
			return report(cmd, in, false)
		},
	}
	c.Flags().StringVar(&runtime, "runtime", "claude", "runtime name in models.by_runtime")
	c.Flags().StringVar(&via, "via", "cli", "cli | profile | anthropic | openai | openrouter")
	c.Flags().StringSliceVar(&exclude, "exclude", nil, "profile: candidates this install does not have (e.g. fable)")
	wd, _ := os.Getwd()
	c.Flags().StringVar(&dir, "root", wd, "repository root")
	return c
}

func modelsShow() *cobra.Command {
	var runtime, dir string
	var asJSON bool
	c := &cobra.Command{
		Use:   "show",
		Short: "Show effective tiers from the cache (no network)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := modelsInput(cmd, dir, runtime)
			if err != nil {
				return err
			}
			return report(cmd, in, asJSON)
		},
	}
	c.Flags().StringVar(&runtime, "runtime", "claude", "runtime name in models.by_runtime")
	c.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	wd, _ := os.Getwd()
	c.Flags().StringVar(&dir, "root", wd, "repository root")
	return c
}

// report resolves and prints; a NO_TIER refusal is printed and returned as an error.
func report(cmd *cobra.Command, in models.Input, asJSON bool) error {
	out := cmd.OutOrStdout()
	et, err := models.Resolve(cmd.Context(), in)
	var ref *core.Refusal
	if err != nil && !errors.As(err, &ref) {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if e := enc.Encode(et); e != nil {
			return e
		}
		return err
	}
	fmt.Fprintf(out, "runtime: %s  catalogue: %s\n", et.Runtime, et.CatalogueSHA)
	for _, t := range core.Tiers {
		switch {
		case et.Models[t] != "":
			fmt.Fprintf(out, "  %-8s %s\n", t, et.Models[t])
		case et.Ladder[t] != "":
			fmt.Fprintf(out, "  %-8s - (uses %s)\n", t, et.Ladder[t])
		default:
			fmt.Fprintf(out, "  %-8s -\n", t)
		}
	}
	for _, d := range models.Degradations(et) {
		fmt.Fprintf(out, "  %s %s -> %s\n", d.Event, d.Tier, d.To)
	}
	return err
}
