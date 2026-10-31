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

func modelsInput(cmd *cobra.Command, dir, runtime string) (models.Input, resolved, error) {
	r, err := resolve(cmd.Context(), dir)
	if err != nil {
		return models.Input{}, r, err
	}
	return models.Input{Spec: r.eff.Policy.Models, Runtime: runtime, Account: models.LocalAccount, Now: time.Now()}, r, nil
}

func modelsProbe() *cobra.Command {
	var runtime, via, dir string
	var exclude []string
	c := &cobra.Command{
		Use:   "probe",
		Short: "Probe the candidates of a runtime and refresh the cache and .rr/tiers.lock (costs tokens)",
		Long: "--via cli runs `<runtime> -p ok --model <m>` (~100 tokens per model); profile trusts the install " +
			"profile (every candidate PASS except --exclude); anthropic|openai|openrouter send one max_tokens:1 " +
			"request per candidate using ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, r, err := modelsInput(cmd, dir, runtime)
			if err != nil {
				return err
			}
			// The cache location comes from the repo policy: it must stay under ~/.cache/riskrails.
			cp, err := models.CachePath(in.Spec.Probe.Cache, r.home)
			if err != nil {
				return err
			}
			in.Cache = models.Cache{Path: cp}
			switch via {
			case "cli":
				in.Prober = models.CLIProber{Name: runtime, Bin: runtime}
			case "profile":
				in.Prober = models.ProfileProber{Name: runtime, Exclude: exclude}
				in.Account = models.ProfileAccount
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
			et, err := models.Resolve(cmd.Context(), in)
			var ref *core.Refusal
			if err != nil && !errors.As(err, &ref) {
				return err
			}
			if werr := models.WriteLock(r.root, et); werr != nil {
				return werr
			}
			return printTiers(cmd, et, err, false)
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
		Short: "Show the tiers in .rr/tiers.lock (what sync and the guard use)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, r, err := modelsInput(cmd, dir, runtime)
			if err != nil {
				return err
			}
			et, err := models.FromLock(in.Spec, r.root, runtime)
			return printTiers(cmd, et, err, asJSON)
		},
	}
	c.Flags().StringVar(&runtime, "runtime", "claude", "runtime name in models.by_runtime")
	c.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	wd, _ := os.Getwd()
	c.Flags().StringVar(&dir, "root", wd, "repository root")
	return c
}

// printTiers prints et; a NO_TIER refusal is printed and returned as an error.
func printTiers(cmd *cobra.Command, et core.EffectiveTiers, err error, asJSON bool) error {
	out := cmd.OutOrStdout()
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
