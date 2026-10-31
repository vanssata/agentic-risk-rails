package ledger

import "github.com/vanssata/agentic-risk-rails/internal/journal"

// SessionData is the Data of a ledger_session event: it ties one runtime
// transcript to a task phase so that `rr cost` can attribute its usage.
type SessionData struct {
	Runtime string `json:"runtime"` // claude | codex
	Session string `json:"session"`
	Phase   string `json:"phase"` // research, plan, implement, review, ...
	Path    string `json:"path"`  // transcript file
}

// EventSession is the journal event type of SessionData.
const EventSession = "ledger_session"

func init() {
	journal.MustRegister(
		journal.Spec{Type: EventSession, Module: "ledger", Doc: "runtime, session, phase, path: links a transcript to a task phase"},
	)
}
