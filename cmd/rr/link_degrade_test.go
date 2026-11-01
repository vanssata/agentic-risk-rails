package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

// The runner (W3-A) refuses L>=2 for anything that is not "sandbox"; the degrade
// runtimes must never report it.
func TestDegradeRuntimesNeverSandbox(t *testing.T) {
	want := map[string]core.Enforcement{"kiro": core.EnforcementCIOnly, "opencode": core.EnforcementCIOnly, "copilot": core.EnforcementHookOnly}
	for name, enf := range want {
		a, ok := runtimes.Lookup(name)
		require.True(t, ok, name)
		got, err := a.Enforcement(context.Background(), t.TempDir())
		require.NoError(t, err)
		assert.Equal(t, enf, got, name)
	}
}
