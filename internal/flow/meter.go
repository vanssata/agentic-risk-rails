package flow

import (
	"context"
	"fmt"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
)

// Meter journals a worker_usage event after every worker run, so `rr cost`
// attributes research, implement and review without a transcript.
type Meter struct {
	Runtime string // claude | codex
	Emit    func(ctx context.Context, typ string, data any) error
	// Check runs before every worker; an error stops it (the budget, DES §3.2).
	Check func(ctx context.Context) error
}

func (e Env) meter(task, runtime string) Meter {
	return Meter{Runtime: runtime, Check: e.budgetCheck(task), Emit: func(ctx context.Context, typ string, data any) error {
		return e.append(ctx, task, typ, core.ActorAutonomy, data)
	}}
}

// phase is the cost phase of a worker role; an unknown role is an error (fail closed).
func phase(role string) (string, error) {
	switch {
	case strings.HasSuffix(role, "-scout"):
		return "research", nil
	case role == "implementer" || role == "fixer":
		return "implement", nil
	case role == "planner":
		return "plan", nil
	case strings.HasPrefix(role, "reviewer"):
		return "review", nil
	}
	return "", fmt.Errorf("flow: no cost phase for worker role %q", role)
}

type metered struct {
	inner core.WorkerRunner
	m     Meter
}

// Wrap returns a runner that journals the usage of every run of r.
func (m Meter) Wrap(r core.WorkerRunner) core.WorkerRunner { return metered{r, m} }

func (w metered) Run(ctx context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	ph, err := phase(spec.Role)
	if err != nil {
		return core.WorkerReport{}, err
	}
	if w.m.Check != nil {
		if err := w.m.Check(ctx); err != nil {
			return core.WorkerReport{}, err
		}
	}
	rep, runErr := w.inner.Run(ctx, spec)
	// a failed run is journaled too, with unknown usage (empty Model), never as free
	data := ledger.WorkerData{Phase: ph, Role: spec.Role, Step: spec.Step, Tier: spec.Tier, Runtime: w.m.Runtime, Status: rep.Status,
		Tokens: rep.Tokens, Calls: rep.Calls, Usage: rep.Usage}
	// the run happened and cost tokens even if ctx was cancelled meanwhile (§14.1)
	if err := w.m.Emit(context.WithoutCancel(ctx), ledger.EventWorker, data); err != nil {
		return rep, err
	}
	return rep, runErr
}

type meteredRO struct {
	inner factory.ReadOnlyRunner
	m     Meter
}

// WrapRO is Wrap for the reviewer side: ReadOnly() yields a metered read-only runner.
func (m Meter) WrapRO(r factory.ReadOnlyRunner) factory.ReadOnlyRunner { return meteredRO{r, m} }

func (w meteredRO) ReadOnly() core.WorkerRunner { return w.m.Wrap(w.inner.ReadOnly()) }
