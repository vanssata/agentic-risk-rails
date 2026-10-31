package research

import "github.com/vanssata/agentic-risk-rails/internal/journal"

func init() {
	journal.MustRegister(
		journal.Spec{Type: "research_scouts_done", Module: "research", Doc: "mode, roles, cache_hits, tokens, calls"},
		journal.Spec{Type: "research_merged", Module: "research", Doc: "facts, conflicts, gaps, brief_tokens"},
	)
}
