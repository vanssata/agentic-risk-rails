package factory

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
)

// stages: spec compliance first, then quality (DES §6).
var stages = []string{"reviewer-spec", "reviewer-quality"}

// roundTier: rounds 1-2 at the mode's tier; round 3 one tier up when that tier
// is effective, else the same tier with a second independent reviewer.
func (f *Factory) roundTier(round int) (tier core.Tier, independent bool) {
	if round < MaxReviewRounds {
		return f.Tier, false
	}
	if r := f.Tier.Rank(); r >= 0 && r+1 < len(core.Tiers) {
		if up := core.Tiers[r+1]; f.Effective[up] != "" {
			return up, false
		}
	}
	return f.Tier, true
}

// pass is true only for an explicit `VERDICT: PASS` line (fail closed).
func pass(body string) bool {
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		if strings.EqualFold(strings.TrimSpace(sc.Text()), "VERDICT: PASS") {
			return true
		}
	}
	return false
}

// review runs up to MaxReviewRounds rounds of spec then quality review. A
// failed round 1 or 2 is followed by one fix batch; a failed round 3 returns
// ok=false (a human decides). rounds is the number of rounds run.
func (f *Factory) review(ctx context.Context, st plan.Step, dir, brief string) (ok bool, rounds int, err error) {
	for round := 1; round <= MaxReviewRounds; round++ {
		rounds = round
		tier, indep := f.roundTier(round)
		findings, err := f.reviewRound(ctx, st, dir, brief, round, tier, indep)
		if err != nil {
			return false, rounds, err
		}
		if findings == "" {
			return true, rounds, nil
		}
		if round == MaxReviewRounds {
			return false, rounds, nil
		}
		fix, err := f.work(ctx, st, "fixer", dir, brief+"\n\nFIX THESE FINDINGS (one batch):\n"+findings)
		if err != nil {
			return false, rounds, err
		}
		if fix.Status != core.StatusDone && fix.Status != core.StatusDoneWithConcerns {
			return false, rounds, fmt.Errorf("factory: fixer of step %s: %s", st.ID, fix.Status)
		}
	}
	return false, rounds, nil
}

// reviewRound returns the findings of the first failing stage, "" if both pass.
func (f *Factory) reviewRound(ctx context.Context, st plan.Step, dir, brief string, round int, tier core.Tier, indep bool) (string, error) {
	diff, err := stage(ctx, dir, st.Files)
	if err != nil {
		return "", err
	}
	for _, role := range stages {
		b := fmt.Sprintf("%s\nREVIEW (%s, round %d). Reply FINDINGS by severity and end with `VERDICT: PASS` or `VERDICT: FAIL`.\n", brief, role, round)
		if indep {
			b += "You are a second, independent reviewer: ignore earlier verdicts.\n"
		}
		rep, err := f.Reviewer.Run(ctx, core.WorkerSpec{Role: role, Tier: tier, Brief: b + "\nDIFF:\n" + diff, Worktree: dir, MaxTurns: f.MaxTurns, Budget: f.Budget})
		if err != nil {
			return "", fmt.Errorf("factory: %s of step %s: %w", role, st.ID, err)
		}
		verdict := "FAIL"
		if pass(rep.Body) {
			verdict = "PASS"
		}
		if err := f.emit(ctx, "review_verdict", map[string]any{"step": st.ID, "stage": role, "round": round, "tier": tier, "verdict": verdict}); err != nil {
			return "", err
		}
		if verdict == "FAIL" {
			return role + ":\n" + rep.Body, nil
		}
	}
	return "", nil
}
