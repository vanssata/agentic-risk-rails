package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

const modelsPolicy = "models:\n  tiers_allowed: [FAST, BALANCED, STRONG, EXPERT]\n  by_runtime:\n    claude: { FAST: [haiku], BALANCED: [sonnet], STRONG: [opus], EXPERT: [fable] }\n"

func TestModelsProbeShow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo := testutil.GitRepo(t, map[string]string{"riskrails.yaml": modelsPolicy})

	// Nothing cached: show refuses.
	out, err := runPolicyRR(t, "models", "show", "--root", repo)
	var ref *core.Refusal
	require.True(t, errors.As(err, &ref), "err=%v out=%s", err, out)
	assert.Equal(t, "NO_TIER", ref.Code)

	// Profile probe without fable, then show reads the cache.
	out, err = runPolicyRR(t, "models", "probe", "--root", repo, "--via", "profile", "--exclude", "fable")
	require.NoError(t, err, out)
	assert.Contains(t, out, "BALANCED sonnet")
	assert.Contains(t, out, "tier_missing EXPERT -> STRONG")
	assert.FileExists(t, filepath.Join(home, ".cache", "riskrails", "models.json"))

	out, err = runPolicyRR(t, "models", "show", "--root", repo, "--json")
	require.NoError(t, err, out)
	assert.Contains(t, out, `"BALANCED": "sonnet"`)
	assert.NotContains(t, out, `"fable"`)

	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		_, err = runPolicyRR(t, "models", "probe", "--root", repo, "--via", "anthropic")
		assert.Error(t, err)
	}
}

func TestModelsProbeRejectsCachePathFromPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	evil := filepath.Join(t.TempDir(), "evil.json")
	repo := testutil.GitRepo(t, map[string]string{"riskrails.yaml": modelsPolicy + "  probe: { cache: \"" + evil + "\" }\n"})
	_, err := runPolicyRR(t, "models", "probe", "--root", repo, "--via", "profile")
	require.Error(t, err)
	assert.NoFileExists(t, evil)
}

func TestModelsProbeWritesLock(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	repo := testutil.GitRepo(t, map[string]string{"riskrails.yaml": modelsPolicy})
	_, err := runPolicyRR(t, "models", "probe", "--root", repo, "--via", "profile", "--exclude", "fable")
	require.NoError(t, err)
	b, err := os.ReadFile(filepath.Join(repo, ".rr", "tiers.lock"))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"BALANCED": "sonnet"`)
	assert.NotContains(t, string(b), "fable")
}
