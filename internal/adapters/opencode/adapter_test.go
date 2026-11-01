package opencode

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/adapters/degrade"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestEnforcementCIOnly(t *testing.T) {
	a := Adapter{degrade.NoHooks{ID: Name}}
	e, err := a.Enforcement(context.Background(), t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementCIOnly, e)
}

func TestPermissionsGolden(t *testing.T) {
	fs, err := permGen{}.Render(context.Background(), core.SyncInput{Policy: fakes.StrictPolicy(), Level: core.L1})
	require.NoError(t, err)
	require.Len(t, fs, 1)
	testutil.Golden(t, "opencode.json", fs[0].Content)
	assert.True(t, json.Valid(fs[0].Content))
	// last matching rule wins: the catch-all must come first
	assert.Regexp(t, `"bash": \{\s*"\*": "ask"`, string(fs[0].Content))
}
