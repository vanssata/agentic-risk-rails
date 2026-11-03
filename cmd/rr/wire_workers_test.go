package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/models"
)

// Host read-only Claude workers load user settings only, so the policy's read
// denies must reach them on the command line (wave 6, W6-C).
func TestWorkersClaudeGetsReadDenies(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Dir(models.LockPath(root)), 0o755))
	require.NoError(t, os.WriteFile(models.LockPath(root), []byte(`{"claude":{"models":{"BALANCED":"sonnet"},"ladder":{}}}`), 0o644))
	var pol core.Policy
	pol.Models.TiersAllowed = []core.Tier{core.TierBalanced}
	pol.Models.ByRuntime = map[string]map[core.Tier][]string{"claude": {core.TierBalanced: {"sonnet"}}}
	pol.Enforcement.SecretReads = []string{".env.local"}
	pol.Enforcement.Sandbox.NoRead = []string{"$secret_reads", "config/secrets/**"}

	impl, ro, _, err := workers(resolved{eff: core.EffectivePolicy{Policy: pol}, root: root}, "claude")
	require.NoError(t, err)
	want := []string{"Read(/.env.local)", "Read(/**/.env.local)", "Read(/config/secrets/**)"}
	assert.Equal(t, want, impl.(factory.ClaudeRunner).DenyRead)
	assert.Equal(t, want, ro.(factory.ClaudeRunner).DenyRead)
}
