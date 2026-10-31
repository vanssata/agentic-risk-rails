package research

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// scoutMaxTurns bounds a scout; DES §5.1 scouts used 8-25 tool calls.
const scoutMaxTurns = 30

// defaultBudget applies when the policy sets no budget_per_scout.
const defaultBudget = 80_000

// Request is one research run.
type Request struct {
	SHA      string
	Question string
	Goal     string
	Known    []string
	Mode     core.Mode
	Inv      Inv
}

// Result is the parsed reports in role order plus how many came from cache.
type Result struct {
	Reports   []Report
	CacheHits int
}

// Run launches the scouts of req.Mode in parallel through the runner, serving
// valid cache entries instead. Any scout failure fails the run.
func Run(ctx context.Context, runner core.WorkerRunner, cacheDir string, spec core.ResearchSpec, req Request) (Result, error) {
	roles, err := RolesFor(spec, req.Mode)
	if err != nil {
		return Result{}, err
	}
	budget := int64(defaultBudget)
	if spec.BudgetPerScout != nil {
		budget = int64(*spec.BudgetPerScout)
	}
	qh := QHash(req.Question)
	reports := make([]Report, len(roles))
	hits := make([]bool, len(roles))
	errs := make([]error, len(roles))
	var wg sync.WaitGroup
	for i, role := range roles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reports[i], hits[i], errs[i] = scout(ctx, runner, cacheDir, spec.Tier, role, qh, budget, req)
		}()
	}
	wg.Wait()
	var res Result
	for i, e := range errs {
		if e != nil {
			return Result{}, fmt.Errorf("research: %s: %w", roles[i], e)
		}
		reports[i].Role = roles[i]
		if hits[i] {
			res.CacheHits++
		}
	}
	res.Reports = reports
	return res, nil
}

func scout(ctx context.Context, runner core.WorkerRunner, dir string, tier core.Tier, role, qh string, budget int64, req Request) (Report, bool, error) {
	if e, ok, err := Get(dir, req.SHA, role, qh, req.Inv); err != nil {
		return Report{}, false, err
	} else if ok {
		r, err := Parse(e.Body)
		return r, true, err
	}
	brief, err := Brief(role, req.Goal, req.Known, budget)
	if err != nil {
		return Report{}, false, err
	}
	rep, err := runner.Run(ctx, core.WorkerSpec{Role: WorkerRole(role), Tier: tier, Brief: brief, MaxTurns: scoutMaxTurns, Budget: core.TokenCount(budget)})
	if err != nil {
		return Report{}, false, err
	}
	if rep.Status != core.StatusDone && rep.Status != core.StatusDoneWithConcerns {
		return Report{}, false, fmt.Errorf("scout status %s", rep.Status)
	}
	r, err := Parse(rep.Body)
	if err != nil {
		return Report{}, false, err
	}
	now := req.Inv.Now
	if now.IsZero() {
		now = time.Now()
	}
	err = Put(dir, Entry{SHA: req.SHA, Role: role, QHash: qh, Body: rep.Body, Read: r.Read, LockHash: req.Inv.LockHash, At: now})
	return r, false, err
}
