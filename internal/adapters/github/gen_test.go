package github

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

func TestRRVersionIsInstallable(t *testing.T) {
	mod, err := os.ReadFile("../../../go.mod")
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindSubmatch(mod)
	require.NotNil(t, m)
	major := regexp.MustCompile(`^v(\d+)\.\d+\.\d+$`).FindStringSubmatch(rrVersion)
	require.NotNil(t, major, "rrVersion must be vMAJOR.MINOR.PATCH")
	if major[1] != "0" && major[1] != "1" {
		assert.Regexp(t, `/v`+major[1]+`$`, string(m[1]), "v2+ needs a /vN module path suffix")
	}
	files, err := gen{}.Render(context.Background(), input(t, t.TempDir()))
	require.NoError(t, err)
	for _, f := range files[2:] {
		assert.Contains(t, string(f.Content), "cmd/rr@v0.5.0\n")
	}
}

func TestNightlySchedule(t *testing.T) {
	for _, on := range []bool{true, false} {
		in := input(t, t.TempDir())
		in.Policy.Policy.Verify.NightlyFull = &on
		files, err := gen{}.Render(context.Background(), in)
		require.NoError(t, err)
		v := string(files[2].Content)
		assert.Equal(t, on, strings.Contains(v, "schedule:"))
		assert.Contains(t, v, "rr verify --full\n", "PR and nightly runs: the whole suite, no task")
		assert.Contains(t, v, "fetch-depth: 0", "a shallow checkout has no origin/<default branch>: sync --check would compare against strict defaults")
	}
}

func TestRegisteredAndNoCollision(t *testing.T) {
	var found bool
	for _, g := range rrsync.Generators() {
		found = found || g.Name() == "github"
	}
	assert.True(t, found)
}

func TestKeepsHandEditedOwner(t *testing.T) {
	for _, owner := range []string{"@acme/security", "@vanssata"} { // team, or a personal repository's user
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, ".github"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, codeownersPath), []byte("riskrails.yaml "+owner+"\n"), 0o644))
		files, err := gen{}.Render(context.Background(), input(t, root))
		require.NoError(t, err)
		assert.Contains(t, string(files[0].Content), "riskrails.yaml "+owner+"\n")
		assert.Contains(t, string(files[0].Content), "/.github/ "+owner+"\n")
		assert.Empty(t, hosting.BotOwners(files[0].Content))
	}
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
