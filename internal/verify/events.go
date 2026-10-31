package verify

import "github.com/vanssata/agentic-risk-rails/internal/journal"

func init() {
	journal.MustRegister(
		journal.Spec{Type: "selection_misses", Module: "verify", Doc: "affected run was green, full run red: changed files, failed adapters (DES §9.2)"},
	)
}
