package models

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Input is everything Resolve needs. Prober nil ⇒ cache only (offline, as in
// `rr sync`): a model counts only with a fresh cached PASS.
type Input struct {
	Spec    core.ModelsSpec // already clamped by the policy ceilings
	Runtime string
	Account string
	Cache   Cache
	Prober  core.ModelProber
	Now     time.Time
	Refresh bool // ignore TTL, probe everything
}

func ttl(s core.ModelsSpec) time.Duration {
	h := 24
	if s.Probe.TTLHours != nil {
		h = *s.Probe.TTLHours
	}
	return time.Duration(h) * time.Hour
}

// Resolve implements DES §4.2. The result holds only PASS models. A missing
// BALANCED yields *core.Refusal{NO_TIER}; the partial result is still returned.
func Resolve(ctx context.Context, in Input) (core.EffectiveTiers, error) {
	cands := in.Spec.ByRuntime[in.Runtime]
	var all []string
	seen := map[string]bool{}
	for _, t := range in.Spec.TiersAllowed {
		for _, m := range cands[t] {
			if !seen[m] {
				seen[m] = true
				all = append(all, m)
			}
		}
	}
	state := map[string]core.ProbeResult{}
	var stale []string
	for _, m := range all {
		r, ok := in.Cache.Get(in.Runtime, in.Account, m)
		if ok {
			state[m] = r
		}
		if !ok || in.Refresh || in.Now.Sub(r.ProbedAt) > ttl(in.Spec) {
			stale = append(stale, m)
		}
	}
	if in.Prober != nil {
		if len(stale) > 0 {
			rs, err := in.Prober.Probe(ctx, stale)
			if err != nil {
				rs = nil // fail-closed: nothing becomes PASS; previous states stay
			}
			for _, r := range rs {
				if r.State == core.ModelUnknown {
					continue // keep the previous state (DES §4.3.2)
				}
				if r.ProbedAt.IsZero() {
					r.ProbedAt = in.Now
				}
				state[r.Model] = r
				_ = in.Cache.Put(in.Runtime, in.Account, r) // a cache write failure is not an availability fact
			}
		}
	} else {
		for _, m := range stale { // offline: expired or missing is not PASS
			delete(state, m)
		}
	}
	et := build(in, cands, state)
	if et.Models[core.TierBalanced] == "" {
		return et, &core.Refusal{Code: "NO_TIER", Detail: "no usable BALANCED model for runtime " + in.Runtime}
	}
	return et, nil
}

func build(in Input, cands map[core.Tier][]string, state map[string]core.ProbeResult) core.EffectiveTiers {
	et := core.EffectiveTiers{Runtime: in.Runtime, Models: map[core.Tier]string{}, Ladder: map[core.Tier]core.Tier{}}
	allowed := map[core.Tier]bool{}
	for _, t := range in.Spec.TiersAllowed {
		allowed[t] = true
	}
	var lines []string
	for _, t := range core.Tiers {
		for _, m := range cands[t] {
			r := state[m]
			st := r.State
			if st == "" {
				st = core.ModelUnknown
			}
			lines = append(lines, fmt.Sprintf("%s=%s", m, st))
			if _, done := et.Models[t]; !done && allowed[t] && st == core.ModelPass {
				et.Models[t] = m
				if r.ProbedAt.After(et.ProbedAt) {
					et.ProbedAt = r.ProbedAt
				}
			}
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(fmt.Sprint(lines)))
	et.CatalogueSHA = hex.EncodeToString(sum[:8])
	for _, t := range core.Tiers {
		if et.Models[t] != "" {
			continue
		}
		next := in.Spec.Ladder.Missing[t] // transitive, bounded walk
		for i := 0; i < len(core.Tiers) && next != "" && et.Models[next] == ""; i++ {
			next = in.Spec.Ladder.Missing[next]
		}
		if next != "" && et.Models[next] != "" {
			et.Ladder[t] = next
		}
	}
	return et
}
