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

// ScoutError is the failure of one scout; other scouts' results are kept.
type ScoutError struct {
	Role   string
	Status core.WorkerStatus // set when the scout reported BLOCKED or NEEDS_CONTEXT
	Err    error
}

func (e *ScoutError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("research: %s scout status %s", e.Role, e.Status)
	}
	return fmt.Sprintf("research: %s scout: %v", e.Role, e.Err)
}

func (e *ScoutError) Unwrap() error { return e.Err }

// Result holds the reports of the scouts that succeeded (role order), how many
// came from cache, and one *ScoutError per scout that failed.
type Result struct {
	Reports   []Report
	CacheHits int
	Errors    []error
}

// Run launches the scouts of req.Mode in parallel through the runner, serving
// valid cache entries instead. Cache problems count as a miss. The returned error
// is only for a bad mode/policy; scout failures are in Result.Errors.
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
			res.Errors = append(res.Errors, e)
			continue
		}
		reports[i].Role = roles[i]
		res.Reports = append(res.Reports, reports[i])
		if hits[i] {
			res.CacheHits++
		}
	}
	return res, nil
}

func scout(ctx context.Context, runner core.WorkerRunner, dir string, tier core.Tier, role, qh string, budget int64, req Request) (Report, bool, error) {
	if e, ok, err := Get(dir, req.SHA, role, qh, req.Inv); err == nil && ok {
		if r, err := Parse(e.Body); err == nil {
			return r, true, nil
		}
	}
	brief, err := Brief(role, req.Goal, req.Known, budget)
	if err != nil {
		return Report{}, false, &ScoutError{Role: role, Err: err}
	}
	rep, err := runner.Run(ctx, core.WorkerSpec{Role: WorkerRole(role), Tier: tier, Brief: brief, MaxTurns: scoutMaxTurns, Budget: core.TokenCount(budget)})
	if err != nil {
		return Report{}, false, &ScoutError{Role: role, Err: err}
	}
	if rep.Status != core.StatusDone && rep.Status != core.StatusDoneWithConcerns {
		return Report{}, false, &ScoutError{Role: role, Status: rep.Status}
	}
	r, err := Parse(rep.Body)
	if err != nil {
		return Report{}, false, &ScoutError{Role: role, Err: err}
	}
	now := req.Inv.Now
	if now.IsZero() {
		now = time.Now()
	}
	if len(req.Inv.Changed) > 0 {
		// the scout read a tree that differs from SHA: caching it under SHA would poison later runs
		return r, false, nil
	}
	// a cache write failure only costs a later miss
	_ = Put(dir, Entry{SHA: req.SHA, Role: role, QHash: qh, Body: rep.Body, Read: r.Read, LockHash: req.Inv.LockHash, At: now})
	return r, false, nil
}
