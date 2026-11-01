package verify

import "github.com/vanssata/agentic-risk-rails/internal/journal"

func init() {
	journal.MustRegister(
		journal.Spec{Type: "selection_misses", Module: "verify", Doc: "affected run was green, full run red: changed files, failed adapters (DES §9.2)"},
		journal.Spec{Type: "verify_started", Module: "verify", Doc: "nonce, full: a full run reserved before it ran (suite_budget counts these)"},
		journal.Spec{Type: "verify_voided", Module: "verify", Doc: "nonce: a reservation refused because suite_budget was exhausted"},
	)
}
