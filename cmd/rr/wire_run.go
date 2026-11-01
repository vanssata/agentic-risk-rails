package main

// Orchestrator wiring after wave 3: rr run reads the kill switch and the policy
// in force through the GitHub client, from the remote pinned in the ceiling
// only (DES §3.4 step 3) — never from GITHUB_REPOSITORY or .git/config.

import (
	"context"
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	hostgh "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

func init() { runHosting = ceilingHosting }

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
