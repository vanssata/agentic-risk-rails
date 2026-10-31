package journal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

func TestRequiredEventsFromDES(t *testing.T) {
	assert.Subset(t, journal.Required(),
		[]string{"task_started", "plan_accepted", "verify_run", "review_verdict", "task_closed"})
	_, ok := journal.Lookup("tiers_resolved")
	assert.True(t, ok)
}

func TestDuplicatePanics(t *testing.T) {
	assert.Panics(t, func() { journal.MustRegister(journal.Spec{Type: "task_started", Module: "x"}) })
	assert.Panics(t, func() { journal.MustRegister(journal.Spec{Type: "no_module"}) })
}
