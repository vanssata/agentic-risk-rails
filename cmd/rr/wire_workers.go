package main

// Worker wiring for `rr task research|build`: Claude and Codex workers with the
// models of the effective tiers. The runtime must be one of project.runtimes
// (nil = all) and have a locked BALANCED model.

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/vanssata/agentic-risk-rails/internal/adapters/claude"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/models"
)

// runnerFor builds the implementer (writes) and the reviewer/scout side (ReadOnly())
// of a runtime. Tests replace it with fakes.
var runnerFor = func(runtime string, m map[core.Tier]string) (core.WorkerRunner, factory.ReadOnlyRunner, error) {
	switch runtime {
	case "claude":
		r := factory.ClaudeRunner{Models: m}
		return r, r, nil
	case "codex":
		r := factory.CodexRunner{Models: m}
		return r, r, nil
	}
	return nil, nil, fmt.Errorf("no worker runner for runtime %q (claude | codex)", runtime)
}

// preflightFor checks that the host workers of `rr task build` can work here
// (trusted repo, working sandbox, writable caches; errata #65). Tests replace it.
var preflightFor = func(ctx context.Context, r resolved, runtime string) error {
	dir := os.Getenv("CLAUDE_CONFIG_DIR")
	if runtime == "codex" {
		dir = os.Getenv("CODEX_HOME")
	}
	return factory.Preflight(ctx, factory.PreflightIn{Runtime: runtime, Root: r.root, ConfigDir: dir, Home: r.home})
}

// workers resolves the runtime's tiers from the lock and builds its runners.
// A tier missing from the lock uses its ladder replacement (DES §4.4).
func workers(r resolved, runtime string) (impl core.WorkerRunner, ro factory.ReadOnlyRunner, et core.EffectiveTiers, err error) {
	if rs := r.eff.Policy.Project.Runtimes; rs != nil && !slices.Contains(rs, runtime) {
		return nil, nil, et, fmt.Errorf("refusing: runtime %q is not in project.runtimes %v", runtime, rs)
	}
	if et, err = models.FromLock(r.eff.Policy.Models, r.root, runtime); err != nil {
		return nil, nil, et, err
	}
	m := map[core.Tier]string{}
	for _, t := range core.Tiers {
		if et.Models[t] != "" {
			m[t] = et.Models[t]
		} else if up := et.Ladder[t]; et.Models[up] != "" {
			m[t] = et.Models[up]
		}
	}
	impl, ro, err = runnerFor(runtime, m)
	if c, ok := impl.(factory.ClaudeRunner); ok { // read-only workers load user settings only
		c.DenyRead = claude.ReadDenyRules(r.eff.Policy)
		impl, ro = c, c
	}
	return impl, ro, et, err
}
