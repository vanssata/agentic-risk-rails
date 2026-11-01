package models_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/adapters/claude"
	"github.com/vanssata/agentic-risk-rails/internal/adapters/codex"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func fixture(t *testing.T) core.EffectivePolicy {
	t.Helper()
	b, err := os.ReadFile(testutil.Fixture(t, "php-symfony/riskrails.yaml"))
	require.NoError(t, err)
	p := core.StrictDefaults()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&p))
	return core.EffectivePolicy{Policy: p, InForce: p, PolicySHA: "fixture"}
}

var modelLine = regexp.MustCompile(`(?m)\bmodel\s*[:=]\s*"?([A-Za-z0-9._/-]+)"?`)

// Generated manifests rendered from the real resolver over a fake probe never
// contain a model whose state is not PASS (DES §4.5a).
func TestManifestsContainOnlyPassModels(t *testing.T) {
	pol := fixture(t)
	states := map[string]map[string]core.ModelState{
		"claude": {"haiku": core.ModelPass, "sonnet": core.ModelPass, "opus": core.ModelFail, "fable": core.ModelFail},
		"codex":  {"gpt-5-nano": core.ModelFail, "gpt-5-mini": core.ModelPass, "gpt-5.3-codex": core.ModelUnknown, "gpt-5": core.ModelFail},
	}
	cache := models.Cache{Path: filepath.Join(t.TempDir(), "models.json")}
	tiers := map[string]core.EffectiveTiers{}
	for rt, st := range states {
		et, err := models.Resolve(context.Background(), models.Input{
			Spec: pol.Policy.Models, Runtime: rt, Account: models.LocalAccount, Cache: cache,
			Prober: fakes.Prober{RuntimeName: rt, States: st}, Now: time.Now(),
		})
		require.NoError(t, err)
		tiers[rt] = et
	}
	in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: pol, Tiers: tiers, Level: core.L1}
	files, err := rrsync.Render(context.Background(), in, append((claude.Adapter{}).Generators(), (codex.Adapter{}).Generators()...))
	require.NoError(t, err)

	seen := 0
	for _, f := range files {
		for _, m := range modelLine.FindAllSubmatch(f.Content, -1) {
			seen++
			name := string(m[1])
			pass := false
			for rt := range states {
				pass = pass || states[rt][name] == core.ModelPass
			}
			assert.True(t, pass, "%s names %q which is not PASS", f.Path, name)
		}
	}
	assert.Positive(t, seen, "no model lines found; the check would be vacuous")
}

func TestMissingBalancedRefuses(t *testing.T) {
	pol := fixture(t)
	_, err := models.Resolve(context.Background(), models.Input{
		Spec: pol.Policy.Models, Runtime: "claude", Account: models.LocalAccount,
		Cache:  models.Cache{Path: filepath.Join(t.TempDir(), "models.json")},
		Prober: fakes.Prober{RuntimeName: "claude", States: map[string]core.ModelState{"haiku": core.ModelPass, "opus": core.ModelPass}}, Now: time.Now(),
	})
	var r *core.Refusal
	require.True(t, errors.As(err, &r))
	assert.Equal(t, "NO_TIER", r.Code)
}
