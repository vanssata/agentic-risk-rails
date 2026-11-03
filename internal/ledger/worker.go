package ledger

import (
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

// WorkerData is the Data of a worker_usage event: one run of a scout,
// implementer or reviewer started by rr (research, build), so that `rr cost`
// attributes it without a transcript. Usage.Model == "" means unknown usage.
type WorkerData struct {
	Phase   string            `json:"phase"` // research, implement, review
	Role    string            `json:"role"`  // code-scout, implementer, reviewer-spec, ...
	Step    string            `json:"step,omitempty"`
	Tier    core.Tier         `json:"tier"`
	Runtime string            `json:"runtime"` // claude | codex
	Status  core.WorkerStatus `json:"status"`
	Tokens  int64             `json:"tokens"`
	Calls   int               `json:"calls"`
	Usage   core.Usage        `json:"usage"`
}

// EventWorker is the journal event type of WorkerData.
const EventWorker = "worker_usage"

func init() {
	journal.MustRegister(
		journal.Spec{Type: EventWorker, Module: "ledger", Doc: "phase, role, step, tier, runtime, status, tokens, calls, usage: one worker run by rr"},
	)
}
