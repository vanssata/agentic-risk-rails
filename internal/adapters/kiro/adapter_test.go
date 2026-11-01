package kiro

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func TestEnforcementCIOnly(t *testing.T) {
	a := New()
	assert.Equal(t, "kiro", a.Name())
	e, err := a.Enforcement(context.Background(), t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementCIOnly, e, "no confirmed blocking hook ⇒ autonomy ≤ L1")
	assert.Empty(t, a.Generators())
}
