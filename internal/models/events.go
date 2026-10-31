package models

import "github.com/vanssata/agentic-risk-rails/internal/journal"

// tiers_resolved and refused are registered by internal/journal (flow).
func init() {
	journal.MustRegister(
		journal.Spec{Type: "tier_missing", Module: "models", Doc: "runtime, tier, to (DES §4.4)"},
		journal.Spec{Type: "autonomy_clamped", Module: "models", Doc: "STRONG missing: autonomy down one level"},
		journal.Spec{Type: "model_marked", Module: "models", Doc: "runtime, model, state, error (probe or runtime error)"},
	)
}
