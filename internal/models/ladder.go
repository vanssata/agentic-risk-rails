package models

import (
	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Degradation is what a missing tier costs (DES §4.4). The caller journals Event.
type Degradation struct {
	Event           string // tier_missing | autonomy_clamped
	Tier            core.Tier
	To              core.Tier
	ExtraReviewPass bool // STRONG missing: full mode adds a second review pass
	ClampAutonomy   bool // STRONG missing: autonomy drops one level
	HalveScouts     bool // FAST missing: scout count is halved
}

// Degradations lists the §4.4 consequences for tiers that policy allows but are missing.
// EXPERT is optional (plan decision 3): its absence is normal and still reported.
func Degradations(et core.EffectiveTiers) []Degradation {
	var out []Degradation
	for _, t := range []core.Tier{core.TierExpert, core.TierStrong, core.TierFast} {
		if et.Models[t] != "" {
			continue
		}
		d := Degradation{Event: "tier_missing", Tier: t, To: et.Ladder[t]}
		out = append(out, d)
		switch t {
		case core.TierStrong:
			out = append(out, Degradation{Event: "autonomy_clamped", Tier: t, To: d.To, ExtraReviewPass: true, ClampAutonomy: true})
		case core.TierFast:
			out[len(out)-1].HalveScouts = true
		}
	}
	return out
}

// Action is the reaction to a runtime error on a tier (DES §4.5).
type Action struct {
	Retry     bool      // same tier again (backoff is the caller's)
	MarkFail  bool      // mark the model FAIL and re-resolve
	Tier      core.Tier // tier to continue on after MarkFail ("" = none)
	Exhausted bool
}

const maxRetries = 3

// OnError decides what happens after errType on tier. thinking steps (plan,
// review, architect) never move to a cheaper tier when never_downgrade_thinking
// is set: TIER_LOST. Rate limits retry 3 times, then QUOTA.
func OnError(spec core.ModelsSpec, et core.EffectiveTiers, tier core.Tier, errType string, thinking bool, attempt int) (Action, error) {
	switch errType {
	case "rate_limit_error", "overloaded_error":
		if attempt < maxRetries {
			return Action{Retry: true}, nil
		}
		return Action{}, &core.Refusal{Code: "QUOTA", Detail: string(tier)}
	case "permission_error", "not_found_error":
		a := Action{MarkFail: true}
		never := spec.Ladder.NeverDowngradeThinking == nil || *spec.Ladder.NeverDowngradeThinking
		if thinking && never {
			return a, &core.Refusal{Code: "TIER_LOST", Detail: string(tier)}
		}
		a.Tier = spec.Ladder.Missing[tier]
		if a.Tier == "" || (et.Models[a.Tier] == "" && et.Ladder[a.Tier] == "") {
			return a, &core.Refusal{Code: "TIER_LOST", Detail: string(tier)}
		}
		return a, nil
	}
	return Action{}, &core.Refusal{Code: "TIER_LOST", Detail: "unclassified error " + errType}
}
