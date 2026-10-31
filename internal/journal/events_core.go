package journal

// Cross-cutting events from DES §16.1 that no single module owns.
// Module-specific events are registered in internal/<module>/events.go.
func init() {
	MustRegister(
		Spec{Type: "task_started", Module: "flow", Required: true, Doc: "weight, mode, policy_sha, tiers_effective"},
		Spec{Type: "plan_accepted", Module: "flow", Required: true, Doc: "by: human | autonomy"},
		Spec{Type: "verify_run", Module: "flow", Required: true, Doc: "affected or full, result"},
		Spec{Type: "review_verdict", Module: "flow", Required: true, Doc: "round, tier, verdict, findings"},
		Spec{Type: "task_closed", Module: "flow", Required: true, Doc: "two facts, cost, review"},
		Spec{Type: "refused", Module: "flow", Doc: "code: NO_TIER | TASK_IN_FLIGHT | CEILING_CHANGED | TIER_LOST | QUOTA | REVIEW_BUDGET | …"},
		Spec{Type: "tiers_resolved", Module: "flow", Doc: "runtime, effective, ladder, catalogue_sha, probed_at"},
		Spec{Type: "policy_clamped", Module: "flow", Doc: "fields cut to the ceiling"},
		Spec{Type: "policy_loosening_ignored", Module: "flow", Doc: "working-tree LOOSEN ignored until merge"},
	)
}
