package factory

import "github.com/vanssata/agentic-risk-rails/internal/journal"

// review rounds are journalled as the existing flow event review_verdict.
func init() {
	journal.MustRegister(
		journal.Spec{Type: "step_started", Module: "factory", Doc: "step, wave, files"},
		journal.Spec{Type: "step_report", Module: "factory", Doc: "step, role, status, tokens, calls"},
		journal.Spec{Type: "step_committed", Module: "factory", Doc: "step, sha: atomic commit of one step, made by rr"},
		journal.Spec{Type: "review_budget", Module: "factory", Doc: "step: three review rounds failed, human decides"},
		journal.Spec{Type: "wave_blocked", Module: "factory", Doc: "wave, step, reason: later waves are not started"},
	)
}
