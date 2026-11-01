package autonomy

import "github.com/vanssata/agentic-risk-rails/internal/journal"

// Events of the runner's own journal (outside the agent sandbox). All of a run's
// events share one journal task, the run id; data.task names the queue item.
// Refusals reuse the core event `refused`.
func init() {
	journal.MustRegister(
		journal.Spec{Type: "autonomy_level", Module: "autonomy", Doc: "task, level, reason, requested; run start also: ceiling_sha, in_force_sha, enforcement"},
		journal.Spec{Type: "run_halted", Module: "autonomy", Doc: "reason: kill switch present or unreadable; the run stops"},
		journal.Spec{Type: "run_budget_exceeded", Module: "autonomy", Doc: "what: wall | tasks_per_day | tokens, limit, used; the run stops"},
		journal.Spec{Type: "ceiling_changed", Module: "autonomy", Doc: "what: ceiling | policy_in_force, was, now; the run stops"},
		journal.Spec{Type: "journal_anchor", Module: "autonomy", Doc: "task, head, bytes: authoritative copy of the in-sandbox journal"},
		journal.Spec{Type: "task_blocked", Module: "autonomy", Doc: "task, status, reason: no PR is opened"},
		journal.Spec{Type: "draft_pr_opened", Module: "autonomy", Doc: "task, branch, number, url"},
	)
}
