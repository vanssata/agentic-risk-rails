package main

// Orchestrator wiring after wave 3: rr run reads the kill switch and the policy
// in force through the GitHub client, from the remote pinned in the ceiling
// only (DES §3.4 step 3) — never from GITHUB_REPOSITORY or .git/config.

import (
	"context"
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	hostgh "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

func init() { runHosting = ceilingHosting }

// runFlow opens a runner task's journal and closes it on the host (errata #41:
// state under stateRoot, outside the checkout; Actor autonomy). The body is
// replaced by flow.Env.Start/Close when internal/flow is merged (W4-A); until
// then it fails closed, so no task runs without a journal and a host-side close.
var runFlow = func(root, stateRoot string) (start func(context.Context, autonomy.Task) error, closeTask func(context.Context, string) error) {
	errNoFlow := fmt.Errorf("internal/flow is not linked: no task journal / host-side close for %s (state %s)", root, stateRoot)
	return func(context.Context, autonomy.Task) error { return errNoFlow },
		func(context.Context, string) error { return errNoFlow }
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
