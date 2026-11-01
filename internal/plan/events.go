package plan

import "github.com/vanssata/agentic-risk-rails/internal/journal"

func init() {
	journal.MustRegister(
		journal.Spec{Type: "plan_checked", Module: "plan", Doc: "steps, waves: rr plan check passed"},
	)
}
