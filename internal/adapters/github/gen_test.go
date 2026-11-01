package github

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	hosting "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func input(t *testing.T, root string) core.SyncInput {
	t.Helper()
	b, err := os.ReadFile(testutil.Fixture(t, "php-symfony/riskrails.yaml"))
	require.NoError(t, err)
	p := core.StrictDefaults()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&p))
	p.Remote = "acme/shop"
	return core.SyncInput{Root: root, Level: core.L1, Policy: core.EffectivePolicy{Policy: p, InForce: p}}
}

func TestGolden(t *testing.T) {
	in := input(t, t.TempDir())
	files, err := gen{}.Render(context.Background(), in)
	require.NoError(t, err)
	again, err := gen{}.Render(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, files, again, "generators must be pure")
	require.Len(t, files, 4)
	for _, f := range files {
		testutil.Golden(t, filepath.ToSlash(f.Path), f.Content)
	}
}

func TestRegisteredAndNoCollision(t *testing.T) {
	var found bool
	for _, g := range rrsync.Generators() {
		found = found || g.Name() == "github"
	}
	assert.True(t, found)
}

func TestKeepsHandEditedTeam(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".github"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, codeownersPath), []byte("riskrails.yaml @acme/security\n"), 0o644))
	files, err := gen{}.Render(context.Background(), input(t, root))
	require.NoError(t, err)
	assert.Contains(t, string(files[0].Content), "riskrails.yaml @acme/security\n")
	assert.Empty(t, hosting.BotOwners(files[0].Content))
}

// The generated ruleset must satisfy the live check that `rr sync --check --remote` applies.
func TestRulesetSatisfiesRemoteCheck(t *testing.T) {
	b, err := ruleset()
	require.NoError(t, err)
	var doc struct {
		Rules json.RawMessage `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(b, &doc))
	missing, err := hosting.MissingRules(doc.Rules, hosting.PolicyCheck)
	require.NoError(t, err)
	assert.Empty(t, missing)
}
