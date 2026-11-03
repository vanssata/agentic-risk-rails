package factory

import (
	"context"
	"fmt"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
)

// stages: spec compliance first, then quality (DES §6).
var stages = []string{"reviewer-spec", "reviewer-quality"}

// roundTier: rounds 1-2 at ReviewTier (empty = Tier); round 3 one tier up when
// that tier is effective, else the same tier with a second independent reviewer.
func (f *Factory) roundTier(round int) (tier core.Tier, independent bool) {
	base := f.Tier
	if f.ReviewTier != "" {
		base = f.ReviewTier
	}
	if round < MaxReviewRounds {
		return base, false
	}
	if r := base.Rank(); r >= 0 && r+1 < len(core.Tiers) {
		if up := core.Tiers[r+1]; f.Effective[up] {
			return up, false
		}
	}
	return base, true
}

// pass: the report is DONE or DONE_WITH_CONCERNS, no `VERDICT:` line says
// FAIL, and the LAST `VERDICT:` line says PASS (fail closed).
func pass(rep core.WorkerReport) bool {
	if rep.Status != core.StatusDone && rep.Status != core.StatusDoneWithConcerns {
		return false
	}
	last := ""
	for _, line := range strings.Split(rep.Body, "\n") {
		v, ok := strings.CutPrefix(strings.ToUpper(strings.TrimSpace(line)), "VERDICT:")
		if !ok {
			continue
		}
		if last = strings.TrimSpace(v); last == "FAIL" {
			return false
		}
	}
	return last == "PASS"
}

// review runs up to MaxReviewRounds rounds of spec then quality review. A
// failed round 1 or 2 is followed by one fix batch; a failed round 3 returns
// ok=false (a human decides). rounds is the number of rounds run; blocked is
// non-empty if a fixer blocked or left the step's scope.
func (f *Factory) review(ctx context.Context, st plan.Step, w worktree, brief string) (ok bool, rounds int, blocked string, err error) {
	for round := 1; round <= MaxReviewRounds; round++ {
		rounds = round
		tier, indep := f.roundTier(round)
		findings, tree, err := f.reviewRound(ctx, st, w, brief, round, tier, indep)
		if err != nil {
			return false, rounds, "", err
		}
		if findings == "" {
			blocked, err := f.verify(ctx, w, st, tree)
			return blocked == "" && err == nil, rounds, blocked, err
		}
		if round == MaxReviewRounds {
			return false, rounds, "", nil
		}
		fix, why, err := f.work(ctx, f.Implementer, st, "fixer", w, brief+"\n\nFIX THESE FINDINGS (one batch):\n"+findings)
		if err != nil || why != "" {
			return false, rounds, why, err
		}
		if fix.Status != core.StatusDone && fix.Status != core.StatusDoneWithConcerns {
			return false, rounds, fmt.Sprintf("fixer %s: %s", fix.Status, firstLine(fix.Body)), nil
		}
	}
	return false, rounds, "", nil
}

// reviewRound returns the findings of the first failing stage, "" if both pass.
func (f *Factory) reviewRound(ctx context.Context, st plan.Step, w worktree, brief string, round int, tier core.Tier, indep bool) (findings, tree string, err error) {
	tree, err = stage(ctx, w, owned(st))
	if err != nil {
		return "", "", err
	}
	patch, err := diff(ctx, w)
	if err != nil {
		return "", "", err
	}
	for _, role := range stages {
		b := fmt.Sprintf("%s\nREVIEW (%s, round %d). You are read-only. Reply with FINDINGS by severity, then a line `VERDICT: PASS` or `VERDICT: FAIL` (exactly one VERDICT line), and as the LAST line `STATUS: DONE`.\n", brief, role, round)
		if indep {
			b += "You are a second, independent reviewer: ignore earlier verdicts.\n"
		}
		rep, err := f.Reviewer.ReadOnly().Run(ctx, core.WorkerSpec{Role: role, Tier: tier, Brief: b + "\nDIFF:\n" + patch, Worktree: w.dir, MaxTurns: f.MaxTurns, Budget: f.Budget, Env: []string{EnvWorker + "=1"}})
		if err != nil {
			return "", "", fmt.Errorf("factory: %s of step %s: %w", role, st.ID, err)
		}
		verdict := "FAIL"
		if pass(rep) {
			verdict = "PASS"
		}
		if err := f.emit(ctx, "review_verdict", map[string]any{"step": st.ID, "stage": role, "round": round, "tier": tier, "verdict": verdict}); err != nil {
			return "", "", err
		}
		if verdict == "FAIL" {
			return role + ":\n" + rep.Body, tree, nil
		}
	}
	return "", tree, nil
}
