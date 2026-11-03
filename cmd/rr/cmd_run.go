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
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/pelletier/go-toml/v2"
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
		var level, queue, runtime, root, image, state, branch, proxyImage, authFrom string
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
				return runQueue(cmd.Context(), cmd, lvl, tasks, runtime, root, image, state, branch, proxyImage, authFrom)
			},
		}
		wd, _ := os.Getwd()
		c.Flags().StringVar(&level, "level", "L2", "autonomy level to run at (L2 or above)")
		c.Flags().StringVar(&queue, "queue", "", "YAML list of tasks: id, brief, mode, irreversible, tier, max_turns, files, declared (axis: 0..2)")
		c.Flags().StringVar(&runtime, "runtime", "claude", "claude | codex")
		c.Flags().StringVar(&root, "root", wd, "clean checkout mounted into the container")
		c.Flags().StringVar(&image, "image", "", "container image pinned by digest (name@sha256:...) with the runtime CLI and rr")
		c.Flags().StringVar(&proxyImage, "proxy-image", "", "squid image pinned by digest (name@sha256:...), present locally: the only way out of the agent container")
		c.Flags().StringVar(&state, "state-dir", "", "runner state outside the checkout (default: $XDG_STATE_HOME/riskrails/<repo-hash>)")
		c.Flags().StringVar(&branch, "default-branch", "main", "default branch on the remote")
		c.Flags().StringVar(&authFrom, "auth-from", "", "isolated subscription login dir (e.g. ~/.claude-rr, ~/.codex-rr), copied per container instead of an API key")
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
			if os.Getenv("RR_POLICY_IN_FORCE") == "" || !runtimeConfigLoads(runtime, root) {
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

// runtimeConfigLoads: Codex reads the project .codex/ layer (profile, hooks) only for a
// trusted project, so the user config in the container's HOME must trust the checkout.
// Claude needs no user config. The rendered project files are checked by the runner.
func runtimeConfigLoads(runtime, root string) bool {
	if runtime != "codex" {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if err != nil {
		return false
	}
	var cfg struct {
		Projects map[string]struct {
			Trust string `toml:"trust_level"`
		} `toml:"projects"`
	}
	return toml.Unmarshal(b, &cfg) == nil && cfg.Projects[root].Trust == "trusted"
}

// noReadPatterns are the checkout patterns to mask in the container: secret_reads
// and sandbox.no_read, "$secret_reads" expanded, other refs dropped.
func noReadPatterns(e core.EnforcementSpec) []string {
	out := slices.Clone(e.SecretReads)
	for _, p := range e.Sandbox.NoRead {
		if !strings.HasPrefix(p, "$") {
			out = append(out, p)
		}
	}
	return out
}

// readOnlyPatterns are the write-protected patterns the container mounts read-only;
// "$name" references point at lists included here (protected_paths) or masked
// anyway (secret_reads).
func readOnlyPatterns(e core.EnforcementSpec) []string {
	var out []string
	for _, p := range slices.Concat(e.ProtectedPaths, e.Sandbox.Readonly, e.Sandbox.NoWrite) {
		if !strings.HasPrefix(p, "$") {
			out = append(out, p)
		}
	}
	return out
}

func runQueue(ctx context.Context, cmd *cobra.Command, lvl core.Level, tasks []autonomy.Task, runtime, root, image, state, branch, proxyImage, authFrom string) error {
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
	hosts := autonomy.RuntimeHosts(runtime)
	if authFrom != "" {
		if authFrom, err = filepath.Abs(authFrom); err != nil {
			return err
		}
		if inside, err := pathWithin(root, authFrom); err != nil || inside {
			return fmt.Errorf("--auth-from %s must be a directory outside the checkout (err: %v)", authFrom, err) //nolint:errorlint // err may be nil
		}
		hosts = autonomy.SubscriptionHosts(runtime)
	}
	sock := filepath.Join(state, "halt.sock")
	return autonomy.Egress{Image: proxyImage, Dir: state, Warn: func(m string) { fmt.Fprintln(cmd.ErrOrStderr(), "warning:", m) },
		Hosts: append(hosts, probe.Policy.Enforcement.Egress.Allow...)}.With(ctx, func(eg *autonomy.EgressNet) error {
		worker := autonomy.DockerRunner{Image: image, Runtime: runtime, Root: root, Sock: sock, Network: eg.Network, ProxyURL: eg.ProxyURL,
			AuthFrom: authFrom, StateDir: state, CodexConfig: filepath.Join(state, autonomy.CodexConfigName), CeilingEnt: filepath.Join(state, autonomy.CeilingEntName),
			CeilingUser: filepath.Join(state, autonomy.CeilingUserName), NoRead: noReadPatterns(probe.Policy.Enforcement), ROPaths: readOnlyPatterns(probe.Policy.Enforcement),
			PolicyFile: filepath.Join(state, autonomy.PolicyFileName), ScopeFile: filepath.Join(state, autonomy.ScopeFileName), Level: lvl, Models: tiers[runtime].Models}
		start, closeTask := runFlow(runFlowIn{Root: root, StateRoot: state, Home: home, Policy: probe, Tiers: tiers[runtime]})
		r := &autonomy.Runner{Start: start, Ceilings: policy.LoadCeilings,
			Close: func(ctx context.Context, id string) error {
				sandbox, cleanup := worker.CloseSandbox()
				defer cleanup(ctx)
				return closeTask(verify.WithSandbox(ctx, sandbox), id)
			}, Root: root, StateDir: state, RunID: "run-" + time.Now().UTC().Format("20060102T150405"),
			DefaultBranch: branch, Level: lvl, Container: true, Runtime: rt, Hosting: host, Journal: journal.New(filepath.Join(state, "run")), Tasks: journal.New(state),
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

// pathWithin reports whether p is root or below it, after resolving symlinks.
func pathWithin(root, p string) (bool, error) {
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, err
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return false, err
	}
	rel, err := filepath.Rel(r, p)
	if err != nil {
		return false, err
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}
