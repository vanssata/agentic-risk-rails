package triage

import "github.com/vanssata/agentic-risk-rails/internal/journal"

func init() {
	journal.MustRegister(
		journal.Spec{Type: "weight_rescored", Module: "triage", Doc: "from/to mode, axes raised by verify or close"},
		journal.Spec{Type: "weight_amended", Module: "triage", Doc: "from/to mode after task start --amend recomputed all six axes"},
	)
}
