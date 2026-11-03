package main

// Orchestrator wiring after wave 3: rr run reads the kill switch and the policy
// in force through the GitHub client, from the remote pinned in the ceiling
// only (DES §3.4 step 3) — never from GITHUB_REPOSITORY or .git/config.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/flow"
	hostgh "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
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

// env is the flow.Env of a runner task. The tree is read per call so it is the one
// the agent leaves behind.
func (in runFlowIn) env(ctx context.Context) (flow.Env, error) {
	tree, err := policy.ListFiles(ctx, in.Root)
	if err != nil {
		return flow.Env{}, fmt.Errorf("tree of %s: %w", in.Root, err)
	}
	return flow.Env{Root: in.Root, StateRoot: in.StateRoot, Policy: in.Policy, Tree: tree,
		Journal: journal.New(in.StateRoot), Home: in.Home,
		Via: "runner", Enforcement: core.EnforcementSandbox, InContainer: true}, nil
}

// runFlow opens a runner task's journal before the agent and closes it on the host
// after it (flow.Env with Actor autonomy, Via runner). The tree is read per call so
// it is the one the agent leaves behind.
var runFlow = func(in runFlowIn) (start func(context.Context, autonomy.Task) (core.Weight, error), closeTask func(context.Context, string) error) {
	env := in.env
	start = func(ctx context.Context, t autonomy.Task) (core.Weight, error) {
		if len(t.Files) == 0 {
			return core.Weight{}, fmt.Errorf("task %s declares no files: the scope guard in the container needs a scope (RR_SCOPE_FILE)", t.ID)
		}
		e, err := env(ctx)
		if err != nil {
			return core.Weight{}, err
		}
		s, err := e.Start(ctx, flow.StartIn{ID: t.ID, Goal: t.Brief, Files: t.Files, Declared: t.Declared, Tiers: in.Tiers,
			Actor: core.ActorAutonomy, Via: "runner"})
		return s.Weight, err
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

// workerTiers: every tier the factory may ask for, a missing one by its ladder
// replacement (as `rr task build`, DES §4.4).
func workerTiers(et core.EffectiveTiers) map[core.Tier]string {
	m := map[core.Tier]string{}
	for _, t := range core.Tiers {
		if et.Models[t] != "" {
			m[t] = et.Models[t]
		} else if up := et.Ladder[t]; et.Models[up] != "" {
			m[t] = et.Models[up]
		}
	}
	return m
}

// runPipeline is the L3/L4 flow of the runner on the real internal/flow: scouts and
// planner through ro (read-only), the plan accepted by the runner itself
// (ActorAutonomy), the factory with impl (implementers) and ro (reviewers). Every
// worker is a DockerRunner in the caller's wiring, so each runs in its own container.
var runPipeline = func(in runFlowIn, impl core.WorkerRunner, ro factory.ReadOnlyRunner, runtime string) *autonomy.Pipeline {
	with := func(ctx context.Context, f func(flow.Env) error) error {
		e, err := in.env(ctx)
		if err != nil {
			return err
		}
		return f(e)
	}
	return &autonomy.Pipeline{
		Research: func(ctx context.Context, id string) error {
			return with(ctx, func(e flow.Env) error { _, err := e.Research(ctx, id, ro.ReadOnly(), runtime); return err })
		},
		Plan: func(ctx context.Context, id string) (file string, err error) {
			err = with(ctx, func(e flow.Env) (perr error) { file, perr = e.Plan(ctx, id, ro.ReadOnly(), runtime); return perr })
			return file, err
		},
		Accept: func(ctx context.Context, id, file string) error {
			return with(ctx, func(e flow.Env) error { return e.Accept(ctx, id, file, core.ActorAutonomy) })
		},
		Build: func(ctx context.Context, id string) error {
			return with(ctx, func(e flow.Env) error {
				_, err := e.Build(ctx, id, flow.BuildIn{Impl: impl, Reviewer: ro, Runtime: runtime, Tiers: in.Tiers.Models, Actor: core.ActorAutonomy})
				return err
			})
		},
		Evidence: func(ctx context.Context, id string) (ev autonomy.Evidence, err error) {
			err = with(ctx, func(e flow.Env) error { ev, err = evidence(ctx, e, id); return err })
			return ev, err
		},
	}
}

// evidence reads what the draft PR shows besides the diff: the accepted plan copy,
// the merged brief, the factory verdicts and the cost by phase.
func evidence(ctx context.Context, e flow.Env, id string) (autonomy.Evidence, error) {
	var ev autonomy.Evidence
	plan, err := os.ReadFile(e.PlanPath(id))
	if err != nil {
		return ev, err
	}
	brief, err := os.ReadFile(e.BriefPath(id))
	if err != nil {
		return ev, err
	}
	events, err := e.Journal.Events(ctx, id)
	if err != nil {
		return ev, err
	}
	var verdicts []string
	for _, x := range events {
		if x.Type == "review_verdict" {
			verdicts = append(verdicts, string(x.Data))
		}
	}
	items, err := ledger.Collect(events, ledger.TranscriptRoots(e.Home, e.StateRoot))
	if err != nil {
		return ev, err
	}
	prices, err := ledger.DefaultPrices()
	if err != nil {
		return ev, err
	}
	cost, err := json.Marshal(ledger.Group(items, prices, "phase"))
	if err != nil {
		return ev, err
	}
	return autonomy.Evidence{Plan: string(plan), Brief: string(brief), Verdict: strings.Join(verdicts, "\n"), Cost: string(cost)}, nil
}

func ceilingHosting(ctx context.Context, _ string) (core.Hosting, error) {
	ent, user, err := policy.LoadCeilings()
	if err != nil {
		return nil, err
	}
	for _, l := range []*core.Layer{ent, user} {
		if l != nil && l.Policy.Remote != "" {
			if _, err := hostgh.TokenFor(ctx, l.Policy.Remote, ""); err != nil { // fail before the run starts
				return nil, err
			}
			return hostgh.Refreshing{Remote: l.Policy.Remote}, nil // a run may outlive one App token
		}
	}
	return nil, fmt.Errorf("no remote pinned in ceiling.yaml: the kill switch and the policy in force cannot be read, refusing to run")
}
