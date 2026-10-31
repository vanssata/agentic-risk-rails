package models

import (
	"context"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// LocalAccount keys cache entries of subscription runtimes (CLI and profile probes).
const LocalAccount = "local"

// ForSync returns SyncInput.Tiers from the cache only; it never probes, so
// `rr sync` stays offline and free. A runtime without a fresh PASS BALANCED
// model is omitted: its generators then leave the model out (agents inherit
// the session model). `rr models probe` fills the cache; `rr models show`
// reports the refusal.
func ForSync(ctx context.Context, spec core.ModelsSpec, home string, now time.Time) map[string]core.EffectiveTiers {
	out := map[string]core.EffectiveTiers{}
	cache := Cache{Path: ExpandPath(spec.Probe.Cache, home)}
	for rt := range spec.ByRuntime {
		et, err := Resolve(ctx, Input{Spec: spec, Runtime: rt, Account: LocalAccount, Cache: cache, Now: now})
		if err == nil {
			out[rt] = et
		}
	}
	return out
}
