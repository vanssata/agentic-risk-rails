package flow

import (
	"context"
	"errors"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Plan runs one read-only planner worker (role "planner", the task's review tier)
// over the task goal, scope and research brief, and writes the plan it returns
// into the task's state (outside the checkout). It returns that file for Accept;
// Plan itself accepts nothing. Used by the unattended runner at L3/L4, where
// Accept(ActorAutonomy) is the plan gate (DES §2.3 step 3: plan_accepted {by: autonomy}).
// Wave 6 stub (W6-B): fail closed.
func (e Env) Plan(ctx context.Context, task string, runner core.WorkerRunner, runtime string) (planFile string, err error) {
	return "", errors.New("flow: Plan not implemented (wave 6, W6-B)")
}
