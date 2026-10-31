package codex

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// loadFixturePolicy is a tiny stand-in for internal/policy: the fixture's
// riskrails.yaml decoded over StrictDefaults().
func loadFixturePolicy(t *testing.T) core.EffectivePolicy {
	t.Helper()
	b, err := os.ReadFile(testutil.Fixture(t, "php-symfony/riskrails.yaml"))
	require.NoError(t, err)
	p := core.StrictDefaults()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&p))
	return core.EffectivePolicy{Policy: p, InForce: p, PolicySHA: "php-symfony"}
}

func codexTiers() map[string]core.EffectiveTiers {
	return map[string]core.EffectiveTiers{"codex": {
		Runtime: "codex",
		Models:  map[core.Tier]string{core.TierBalanced: "gpt-5-mini", core.TierStrong: "gpt-5.3-codex"},
		Ladder:  map[core.Tier]core.Tier{core.TierFast: core.TierBalanced},
	}}
}

func render(t *testing.T, in core.SyncInput) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, g := range (Adapter{}).Generators() {
		fs, err := g.Render(context.Background(), in)
		require.NoError(t, err)
		again, err := g.Render(context.Background(), in)
		require.NoError(t, err)
		assert.Equal(t, fs, again, "generators must be pure")
		for _, f := range fs {
			out[f.Path] = string(f.Content)
		}
	}
	return out
}

func TestGoldens(t *testing.T) {
	cases := []struct {
		name   string
		policy core.EffectivePolicy
		tiers  map[string]core.EffectiveTiers
	}{
		{"strict", fakes.StrictPolicy(), nil},
		{"strict-tiers", fakes.StrictPolicy(), codexTiers()},
		{"php-symfony", loadFixturePolicy(t), codexTiers()},
	}
	for _, c := range cases {
		for _, lvl := range []core.Level{core.L1, core.L2} {
			t.Run(c.name+"-"+lvl.String(), func(t *testing.T) {
				files := render(t, core.SyncInput{Root: "/repo", Home: "/home/test", Policy: c.policy, Tiers: c.tiers, Level: lvl})
				require.Len(t, files, 2)
				testutil.Golden(t, c.name+"-"+lvl.String()+"/config.toml", []byte(files[".codex/config.toml"]))
				testutil.Golden(t, c.name+"-"+lvl.String()+"/hooks.json", []byte(files[".codex/hooks.json"]))
			})
		}
	}
}

func TestConfigSemantics(t *testing.T) {
	in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: loadFixturePolicy(t), Tiers: codexTiers(), Level: core.L1}
	var cfg map[string]any
	require.NoError(t, toml.Unmarshal([]byte(render(t, in)[".codex/config.toml"]), &cfg))
	assert.Equal(t, "workspace-write", cfg["sandbox_mode"])
	assert.Equal(t, "on-request", cfg["approval_policy"])
	assert.Equal(t, "riskrails", cfg["default_permissions"])
	assert.Equal(t, false, cfg["sandbox_workspace_write"].(map[string]any)["network_access"])

	fs := cfg["permissions"].(map[string]any)["riskrails"].(map[string]any)["filesystem"].(map[string]any)
	ws := fs[":workspace_roots"].(map[string]any)
	assert.Equal(t, "write", ws["."])
	assert.Equal(t, "read", ws["riskrails.yaml"])
	assert.Equal(t, "read", ws[".github/**"])
	assert.Equal(t, "deny", ws["config/secrets/**"], "$secret_reads expanded")
	assert.Equal(t, "deny", ws[".env.local"])
	assert.Equal(t, "deny", fs["/home/test/.ssh/**"], "~ expanded to Home")
	assert.Equal(t, "deny", fs["/home/test/.config/riskrails/**"])
	assert.Equal(t, "read", fs["/"])
	for k := range ws {
		assert.False(t, strings.HasPrefix(k, ".git/"), "no .git rules: %s", k)
	}

	in.Level = core.L2
	require.NoError(t, toml.Unmarshal([]byte(render(t, in)[".codex/config.toml"]), &cfg))
	assert.Equal(t, "never", cfg["approval_policy"])
}

func TestStrictestAccessWins(t *testing.T) {
	p := core.StrictDefaults()
	p.Enforcement.Sandbox = core.SandboxSpec{
		Readonly: []string{"a/**"}, NoRead: []string{"a/**", "$secret_reads"}, NoWrite: []string{".env*"},
	}
	p.Enforcement.SecretReads = []string{".env*"}
	fs := filesystem(core.SyncInput{Home: "/h", Policy: core.EffectivePolicy{Policy: p}})
	ws := fs[":workspace_roots"].(map[string]string)
	assert.Equal(t, "deny", ws["a/**"])
	assert.Equal(t, "deny", ws[".env*"])
}

func TestHooksFile(t *testing.T) {
	in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: fakes.StrictPolicy(), Level: core.L1}
	h := render(t, in)[".codex/hooks.json"]
	assert.Contains(t, h, `"command": "rr guard --runtime codex --event PreToolUse || exit 2"`)
	assert.Contains(t, h, `"timeout": 10`)
	assert.Contains(t, h, "Bash|apply_patch|mcp__.*")
	assert.True(t, strings.HasSuffix(h, "}\n"))
}

// A model string may only reach the output via in.Tiers["codex"], never from
// policy candidates (DES §4.3 / ADR-4).
func TestModelNeverAppearsUnlessEffective(t *testing.T) {
	candidates := []string{"gpt-5-nano", "gpt-5-mini", "gpt-5.3-codex", "gpt-5"} // php-symfony by_runtime
	pol := loadFixturePolicy(t)
	eff := func(models map[core.Tier]string, ladder map[core.Tier]core.Tier) map[string]core.EffectiveTiers {
		return map[string]core.EffectiveTiers{"codex": {Runtime: "codex", Models: models, Ladder: ladder}}
	}
	cases := []struct {
		name  string
		tiers map[string]core.EffectiveTiers
		want  string // "" = no model key at all
	}{
		{"no tiers at all", nil, ""},
		{"no codex entry", map[string]core.EffectiveTiers{"claude": {Models: map[core.Tier]string{core.TierBalanced: "sonnet"}}}, ""},
		{"empty models", eff(nil, nil), ""},
		{"only STRONG, no ladder", eff(map[core.Tier]string{core.TierStrong: "x-strong"}, nil), ""},
		{"only FAST", eff(map[core.Tier]string{core.TierFast: "x-fast"}, nil), ""},
		{"BALANCED present", eff(map[core.Tier]string{core.TierBalanced: "x-bal"}, nil), "x-bal"},
		{"BALANCED via ladder", eff(map[core.Tier]string{core.TierStrong: "x-strong"}, map[core.Tier]core.Tier{core.TierBalanced: core.TierStrong}), "x-strong"},
		{"ladder cycle", eff(nil, map[core.Tier]core.Tier{core.TierBalanced: core.TierFast, core.TierFast: core.TierBalanced}), ""},
		{"ladder self loop", eff(nil, map[core.Tier]core.Tier{core.TierBalanced: core.TierBalanced}), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: pol, Tiers: c.tiers, Level: core.L1}
			out := render(t, in)[".codex/config.toml"]
			for _, cand := range candidates {
				assert.NotContains(t, out, cand, "policy candidate leaked")
			}
			for _, m := range []string{"x-strong", "x-fast", "x-bal", "sonnet"} {
				if m != c.want {
					assert.NotContains(t, out, m)
				}
			}
			if c.want == "" {
				assert.NotContains(t, out, "default_subagent_model")
				assert.NotContains(t, out, "default_subagent_reasoning_effort")
			} else {
				assert.Contains(t, out, `default_subagent_model = '`+c.want+`'`)
			}
		})
	}
}
