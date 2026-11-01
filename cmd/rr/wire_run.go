package main

// Orchestrator wiring after wave 3: rr run reads the kill switch and the policy
// in force through the GitHub client, from the remote pinned in the ceiling
// only (DES §3.4 step 3) — never from GITHUB_REPOSITORY or .git/config.

import (
	"context"
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/flow"
	hostgh "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

func init() { runHosting = ceilingHosting }

// runFlowIn is what the runner's task flow needs: the checkout, the runner-owned
// state outside it (journal and baseline, errata #41), the policy resolved at start.
type runFlowIn struct {
	Root, StateRoot, Home string
	Policy                core.EffectivePolicy
	Tiers                 core.EffectiveTiers
}

// runFlow opens a runner task's journal before the agent and closes it on the host
// after it (flow.Env with Actor autonomy, Via runner). The tree is read per call so
// it is the one the agent leaves behind.
var runFlow = func(in runFlowIn) (start func(context.Context, autonomy.Task) error, closeTask func(context.Context, string) error) {
	env := func(ctx context.Context) (flow.Env, error) {
		tree, err := policy.ListFiles(ctx, in.Root)
		if err != nil {
			return flow.Env{}, fmt.Errorf("tree of %s: %w", in.Root, err)
		}
		return flow.Env{Root: in.Root, StateRoot: in.StateRoot, Policy: in.Policy, Tree: tree,
			Journal: journal.New(in.StateRoot), Home: in.Home}, nil
	}
	start = func(ctx context.Context, t autonomy.Task) error {
		if len(t.Files) == 0 {
			return fmt.Errorf("task %s declares no files: the scope guard in the container needs a scope (RR_SCOPE_FILE)", t.ID)
		}
		e, err := env(ctx)
		if err != nil {
			return err
		}
		_, err = e.Start(ctx, flow.StartIn{ID: t.ID, Goal: t.Brief, Files: t.Files, Tiers: in.Tiers,
			Actor: core.ActorAutonomy, Via: "runner"})
		return err
	}
	closeTask = func(ctx context.Context, id string) error {
		e, err := env(ctx)
		if err != nil {
			return err
		}
		return e.Close(ctx, flow.CloseIn{Task: id, Actor: core.ActorAutonomy})
	}
	return start, closeTask
}

func ceilingHosting(context.Context, string) (core.Hosting, error) {
	ent, user, err := policy.LoadCeilings()
	if err != nil {
		return nil, err
	}
	for _, l := range []*core.Layer{ent, user} {
		if l != nil && l.Policy.Remote != "" {
			return hostgh.New(l.Policy.Remote, hostgh.TokenFromEnv(), "")
		}
	}
	return nil, fmt.Errorf("no remote pinned in ceiling.yaml: the kill switch and the policy in force cannot be read, refusing to run")
}
