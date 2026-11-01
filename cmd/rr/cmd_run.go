package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// runHosting builds the hosting client for the repo (reads the pinned `remote`
// of the ceiling). The GitHub client (W3-B) replaces this; until then `rr run`
// fails closed because the kill switch cannot be read.
var runHosting = func(context.Context, string) (core.Hosting, error) {
	return nil, fmt.Errorf("no hosting client linked: the kill switch and the policy in force cannot be read, refusing to run")
}

func init() {
	cli.Register(func() *cobra.Command {
		var level, queue, runtime, root, image, state, branch, proxyImage string
		c := &cobra.Command{
			Use:   "run",
			Short: "Unattended runner: queue of light tasks in a container, draft PRs only (L2+)",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				var lvl core.Level
				if err := lvl.UnmarshalText([]byte(level)); err != nil {
					return err
				}
				raw, err := os.ReadFile(queue)
				if err != nil {
					return err
				}
				var tasks []autonomy.Task
				dec := yaml.NewDecoder(bytes.NewReader(raw))
				dec.KnownFields(true)
				if err := dec.Decode(&tasks); err != nil {
					return fmt.Errorf("queue %s: %w", queue, err)
				}
				return runQueue(cmd.Context(), cmd, lvl, tasks, runtime, root, image, state, branch, proxyImage)
			},
		}
		wd, _ := os.Getwd()
		c.Flags().StringVar(&level, "level", "L2", "autonomy level to run at (L2 or above)")
		c.Flags().StringVar(&queue, "queue", "", "YAML list of tasks: id, brief, mode, irreversible, tier, max_turns")
		c.Flags().StringVar(&runtime, "runtime", "claude", "claude | codex")
		c.Flags().StringVar(&root, "root", wd, "clean checkout mounted into the container")
		c.Flags().StringVar(&image, "image", "", "container image pinned by digest (name@sha256:...) with the runtime CLI and rr")
		c.Flags().StringVar(&proxyImage, "proxy-image", "", "squid image pinned by digest (name@sha256:...), present locally: the only way out of the agent container")
		c.Flags().StringVar(&state, "state-dir", "", "runner state outside the checkout (default: $XDG_STATE_HOME/riskrails/<repo-hash>)")
		c.Flags().StringVar(&branch, "default-branch", "main", "default branch on the remote")
		_ = c.MarkFlagRequired("queue")
		_ = c.MarkFlagRequired("image")
		c.AddCommand(enforcementCmd())
		return c
	})
}

// probeCalls are known-bad tool calls the real guard must deny (errata #42).
func probeCalls(runtime, root string) []core.ToolCall {
	yaml := filepath.Join(root, "riskrails.yaml")
	return []core.ToolCall{
		{Runtime: runtime, Tool: "Bash", Command: "rr task close", Cwd: root},
		{Runtime: runtime, Tool: "Write", Paths: []string{yaml}, Content: "x", Cwd: root,
			Edits: []core.FileEdit{{Path: yaml, Content: "x"}}},
	}
}

// probeRules are the rule prefixes that prove the RIGHT rule denied the call; a
// deny from guard.fail_closed (broken policy, unreadable env) proves nothing.
var probeRules = [][]string{
	{"core.AlwaysDeniedCommands:"},
	{"enforcement.protected_paths:", "core.AlwaysProtected:"},
}

func deniedByRule(v core.Verdict, prefixes []string) bool {
	if v.Decision != core.Deny {
		return false
	}
	for _, p := range prefixes {
		if strings.HasPrefix(v.Rule, p) {
			return true
		}
	}
	return false
}

// enforcementCmd is the functional probe the runner executes inside the agent's
// image (errata #42): in the runner's container the container is the sandbox, so
// it prints `sandbox` only if RR_POLICY_IN_FORCE marks that container and the real
// guard denies every known-bad call; anything else prints `hook_only`. No LookPath.
func enforcementCmd() *cobra.Command {
	var runtime, root string
	c := &cobra.Command{
		Use:   "enforcement",
		Short: "Print the enforcement level of this environment (run inside the agent image)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, ok := runtimes.Lookup(runtime); !ok {
				return fmt.Errorf("unknown runtime %q", runtime)
			}
			enf := core.EnforcementSandbox
			if os.Getenv("RR_POLICY_IN_FORCE") == "" {
				enf = core.EnforcementHookOnly
			}
			for i, call := range probeCalls(runtime, root) {
				if !deniedByRule(check(cmd.Context(), call, runtime), probeRules[i]) {
					enf = core.EnforcementHookOnly
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), enf)
			return nil
		},
	}
	wd, _ := os.Getwd()
	c.Flags().StringVar(&runtime, "runtime", "claude", "claude | codex")
	c.Flags().StringVar(&root, "root", wd, "checkout")
	return c
}

func runQueue(ctx context.Context, cmd *cobra.Command, lvl core.Level, tasks []autonomy.Task, runtime, root, image, state, branch, proxyImage string) error {
	// SIGINT/SIGTERM cancel the context instead of killing rr, so the proxy and
	// the networks below are removed on every exit.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	rt, ok := runtimes.Lookup(runtime)
	if !ok {
		return fmt.Errorf("unknown runtime %q", runtime)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	host, err := runHosting(ctx, root)
	if err != nil {
		return err
	}
	// DES §3.4 step 4: L≥2 only with the live ruleset in place (code-owner
	// review, last-push approval, pinned status check, no bypass actors).
	if err := remoteCheck(ctx, branch, cmd.ErrOrStderr()); err != nil {
		return err
	}
	if state == "" {
		if state, err = defaultStateDir(root); err != nil {
			return err
		}
	}
	home, _ := os.UserHomeDir()
	svc := policy.New()
	resolve := func(ctx context.Context, inForce []byte) (core.EffectivePolicy, error) {
		p, err := policy.Load(inForce)
		if err != nil {
			return core.EffectivePolicy{}, err
		}
		ent, user, err := policy.LoadCeilings()
		if err != nil {
			return core.EffectivePolicy{}, err
		}
		return svc.Resolve(ctx, core.PolicyLayers{Enterprise: ent, User: user,
			DefaultBranch: &core.Layer{Policy: p, Raw: inForce, Source: "api:" + branch + ":riskrails.yaml"}})
	}
	// Models come from the committed .rr/tiers.lock; the policy is only needed for its candidates.
	inForce, err := host.ReadFile(ctx, branch, "riskrails.yaml")
	if err != nil {
		return fmt.Errorf("policy in force: %w", err)
	}
	probe, err := resolve(ctx, inForce)
	if err != nil {
		return err
	}
	tiers := models.ForSync(ctx, probe.Policy.Models, root)
	if proxyImage == "" {
		return fmt.Errorf("--proxy-image is required: the agent reaches the runtime API only through the egress proxy, there is no open-network fallback")
	}
	sock := filepath.Join(state, "halt.sock")
	return autonomy.Egress{Image: proxyImage, Dir: state, Warn: func(m string) { fmt.Fprintln(cmd.ErrOrStderr(), "warning:", m) },
		Hosts: append(autonomy.RuntimeHosts(runtime), probe.Policy.Enforcement.Egress.Allow...)}.With(ctx, func(eg *autonomy.EgressNet) error {
		worker := autonomy.DockerRunner{Image: image, Runtime: runtime, Root: root, Sock: sock, Network: eg.Network, ProxyURL: eg.ProxyURL,
			PolicyFile: filepath.Join(state, autonomy.PolicyFileName), ScopeFile: filepath.Join(state, autonomy.ScopeFileName), Level: lvl, Models: tiers[runtime].Models}
		start, closeTask := runFlow(runFlowIn{Root: root, StateRoot: state, Home: home, Policy: probe, Tiers: tiers[runtime]})
		r := &autonomy.Runner{Start: start,
			Close: func(ctx context.Context, id string) error {
				sandbox, cleanup := worker.CloseSandbox()
				defer cleanup(ctx)
				return closeTask(verify.WithSandbox(ctx, sandbox), id)
			}, Root: root, StateDir: state, RunID: "run-" + time.Now().UTC().Format("20060102T150405"),
			DefaultBranch: branch, Level: lvl, Container: true, Runtime: rt, Hosting: host, Journal: journal.New(state),
			Worker: worker, Probe: worker.Probe, Resolve: resolve, Gens: rrsync.Generators(), Tiers: tiers, Home: home, HaltSock: sock}
		out, err := r.Run(ctx, tasks)
		for _, o := range out {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", o.Task, o.Level, o.Status, o.PR.URL)
		}
		return err
	})
}

// defaultStateDir is $XDG_STATE_HOME/riskrails/<hash of the checkout path>, so the
// daily task count survives runs. Not ~/.config or ~/.cache.
func defaultStateDir(root string) (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	h := sha256.Sum256([]byte(root))
	return filepath.Join(base, "riskrails", hex.EncodeToString(h[:8])), nil
}
