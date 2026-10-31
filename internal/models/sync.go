package models

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// LockPath is the committed lock that manifests and the guard render from.
func LockPath(root string) string { return filepath.Join(root, ".rr", "tiers.lock") }

type lockEntry struct {
	Models map[core.Tier]string    `json:"models"`
	Ladder map[core.Tier]core.Tier `json:"ladder"`
}

func readLock(root string) map[string]lockEntry {
	b, err := os.ReadFile(LockPath(root))
	if err != nil {
		return nil
	}
	var l map[string]lockEntry
	if json.Unmarshal(b, &l) != nil {
		return nil // unreadable lock: nothing is PASS
	}
	return l
}

// WriteLock stores the PASS models and ladder of et. A runtime without a
// BALANCED model is removed from the lock. Output is deterministic (sorted keys, no times).
func WriteLock(root string, et core.EffectiveTiers) error {
	l := readLock(root)
	if l == nil {
		l = map[string]lockEntry{}
	}
	if et.Models[core.TierBalanced] == "" {
		delete(l, et.Runtime)
	} else {
		l[et.Runtime] = lockEntry{Models: et.Models, Ladder: et.Ladder}
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(LockPath(root)), 0o755); err != nil {
		return err
	}
	return os.WriteFile(LockPath(root), append(b, '\n'), 0o644)
}

// FromLock returns the tiers of one runtime from the lock. The policy is
// LOOSEN-protected and the lock is not, so a model that is not a candidate of
// its tier (or whose tier is not allowed) is dropped, and the ladder is rebuilt
// from the policy. No valid BALANCED ⇒ NO_TIER.
func FromLock(spec core.ModelsSpec, root, runtime string) (core.EffectiveTiers, error) {
	et := core.EffectiveTiers{Runtime: runtime, Models: map[core.Tier]string{}}
	for t, m := range readLock(root)[runtime].Models {
		if slices.Contains(spec.TiersAllowed, t) && slices.Contains(spec.ByRuntime[runtime][t], m) {
			et.Models[t] = m
		}
	}
	et.Ladder = ladderOf(spec, et.Models)
	if et.Models[core.TierBalanced] == "" {
		return et, &core.Refusal{Code: "NO_TIER", Detail: "no locked BALANCED model for runtime " + runtime + " (run rr models probe)"}
	}
	return et, nil
}

// ForSync returns SyncInput.Tiers (and the guard's tiers) from the lock only:
// no probe, cache, TTL or HOME. A runtime without a valid BALANCED is omitted,
// so its generators leave the model out; `rr models show` reports NO_TIER.
func ForSync(_ context.Context, spec core.ModelsSpec, root string) map[string]core.EffectiveTiers {
	out := map[string]core.EffectiveTiers{}
	for rt := range spec.ByRuntime {
		if et, err := FromLock(spec, root, rt); err == nil {
			out[rt] = et
		}
	}
	return out
}
