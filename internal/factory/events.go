package factory

import "github.com/vanssata/agentic-risk-rails/internal/journal"

// review rounds are journalled as the existing flow event review_verdict.
func init() {
	journal.MustRegister(
		journal.Spec{Type: "step_started", Module: "factory", Doc: "step, wave, files: the step worktree exists"},
		journal.Spec{Type: "step_report", Module: "factory", Doc: "step, role, status, tokens, calls"},
		journal.Spec{Type: "scope_violation", Module: "factory", Doc: "step, reason: out-of-scope change, symlink or filter attribute; step is BLOCKED"},
		journal.Spec{Type: "step_committed", Module: "factory", Doc: "step, sha: atomic commit of one step in its worktree, made by rr"},
		journal.Spec{Type: "step_integrated", Module: "factory", Doc: "step, sha: the step commit cherry-picked into the integration checkout"},
		journal.Spec{Type: "review_budget", Module: "factory", Doc: "step: three review rounds failed, human decides"},
		journal.Spec{Type: "wave_blocked", Module: "factory", Doc: "wave, step, reason: later waves are not started"},
	)
}
