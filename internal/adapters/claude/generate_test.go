package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// fixturePolicy loads testdata/php-symfony/riskrails.yaml over StrictDefaults.
func fixturePolicy(t *testing.T) core.EffectivePolicy {
	t.Helper()
	b, err := os.ReadFile(testutil.Fixture(t, "php-symfony/riskrails.yaml"))
	require.NoError(t, err)
	p := core.StrictDefaults()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&p))
	return core.EffectivePolicy{Policy: p, InForce: p, PolicySHA: "fixture"}
}

func claudeTiers() map[string]core.EffectiveTiers {
	return map[string]core.EffectiveTiers{Name: {
		Runtime: Name,
		Models:  map[core.Tier]string{core.TierFast: "haiku", core.TierBalanced: "sonnet", core.TierStrong: "opus"},
		Ladder:  map[core.Tier]core.Tier{core.TierExpert: core.TierStrong, core.TierStrong: core.TierBalanced, core.TierFast: core.TierBalanced},
	}}
}

func render(t *testing.T, in core.SyncInput) []core.File {
	t.Helper()
	var all []core.File
	for _, g := range (Adapter{}).Generators() {
		fs, err := g.Render(context.Background(), in)
		require.NoError(t, err)
		all = append(all, fs...)
	}
	return all
}

func TestGoldens(t *testing.T) {
	policies := map[string]core.EffectivePolicy{"strict": fakes.StrictPolicy(), "symfony": fixturePolicy(t)}
	for pname, pol := range policies {
		for _, lvl := range []core.Level{core.L1, core.L2} {
			in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: pol, Tiers: claudeTiers(), Level: lvl}
			for _, f := range render(t, in) {
				name := pname + "-" + lvl.String() + "/" + f.Path
				t.Run(name, func(t *testing.T) { testutil.Golden(t, name, f.Content) })
			}
		}
	}
}

// Every protected path and secret read must be backed by BOTH a permission rule
// and the OS sandbox, and slash-less patterns must cover any depth.
func TestProtectedPathsBackedBySandboxAndRules(t *testing.T) {
	pol := fixturePolicy(t)
	in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: pol, Level: core.L1}
	var doc struct {
		Permissions struct{ Deny []string }
		Sandbox     struct {
			Filesystem struct{ DenyRead, DenyWrite []string }
		}
	}
	require.NoError(t, json.Unmarshal(render(t, in)[0].Content, &doc))
	e := pol.Policy.Enforcement
	write := append(append(append([]string{}, core.AlwaysProtected...), e.ProtectedPaths...), e.Sandbox.Readonly...)
	for _, p := range write {
		want := p
		if !strings.Contains(p, "/") {
			assert.Contains(t, doc.Sandbox.Filesystem.DenyWrite, "**/"+p, p)
			assert.Contains(t, doc.Permissions.Deny, "Edit(/**/"+p+")", p)
			want = p
		}
		assert.Contains(t, doc.Sandbox.Filesystem.DenyWrite, want, p)
		assert.Contains(t, doc.Permissions.Deny, "Edit(/"+p+")", p)
	}
	assert.Contains(t, doc.Sandbox.Filesystem.DenyWrite, ".claude/**")
	assert.Contains(t, doc.Sandbox.Filesystem.DenyWrite, ".git/**")
	for _, p := range []string{".env.local", "config/secrets/**"} {
		assert.Contains(t, doc.Sandbox.Filesystem.DenyRead, p)
		assert.Contains(t, doc.Permissions.Deny, "Read(/"+p+")")
	}
	assert.Contains(t, doc.Sandbox.Filesystem.DenyRead, "**/.env.local")
	assert.Contains(t, doc.Sandbox.Filesystem.DenyRead, "~/.ssh/**", "~ stays literal: manifests must not depend on the machine")
	assert.Contains(t, doc.Permissions.Deny, "Read(~/.ssh/**)")
}

func TestDeterministic(t *testing.T) {
	in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: fixturePolicy(t), Tiers: claudeTiers(), Level: core.L1}
	assert.Equal(t, render(t, in), render(t, in))
}

func TestAskBecomesDenyAtL2(t *testing.T) {
	pol := fixturePolicy(t)
	for _, c := range []struct {
		lvl    core.Level
		askLen int
		inDeny bool
	}{{core.L1, 4, false}, {core.L2, 0, true}} {
		in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: pol, Level: c.lvl}
		out := string(render(t, in)[0].Content)
		assert.Equal(t, c.inDeny, strings.Contains(sectionOf(out, "deny"), "Bash(git push*)"), c.lvl)
		if c.askLen == 0 {
			assert.Contains(t, out, `"ask": []`)
		} else {
			assert.Contains(t, sectionOf(out, "ask"), "Bash(git push*)")
		}
	}
}

func sectionOf(doc, key string) string {
	i := strings.Index(doc, `"`+key+`": [`)
	j := strings.Index(doc[i:], "]")
	return doc[i : i+j]
}

// No generated file may name a model that is not a PASS model in Tiers.Models.
func TestModelNeverAppearsUnlessInModels(t *testing.T) {
	const poison = "claude-poison-9"
	all := map[core.Tier]string{core.TierFast: "m-fast", core.TierBalanced: "m-bal", core.TierStrong: "m-strong", core.TierExpert: "m-expert"}
	ladder := map[core.Tier]core.Tier{core.TierExpert: core.TierStrong, core.TierStrong: core.TierBalanced, core.TierFast: core.TierBalanced}
	cycle := map[core.Tier]core.Tier{core.TierFast: core.TierStrong, core.TierStrong: core.TierFast}
	cases := []struct {
		name   string
		tiers  map[string]core.EffectiveTiers
		models map[string]string // file -> expected model ("" = no model line)
	}{
		{"all", tiers(all, ladder), map[string]string{"rr-scout": "m-fast", "rr-implementer": "m-bal", "rr-reviewer": "m-strong"}},
		{"no STRONG", tiers(without(all, core.TierStrong, core.TierExpert), ladder), map[string]string{"rr-scout": "m-fast", "rr-implementer": "m-bal", "rr-reviewer": "m-bal"}},
		{"no EXPERT", tiers(without(all, core.TierExpert), ladder), map[string]string{"rr-scout": "m-fast", "rr-implementer": "m-bal", "rr-reviewer": "m-strong"}},
		{"no FAST", tiers(without(all, core.TierFast), ladder), map[string]string{"rr-scout": "m-bal", "rr-implementer": "m-bal", "rr-reviewer": "m-strong"}},
		{"only FAST, ladder cycle", tiers(map[core.Tier]string{core.TierFast: "m-fast"}, cycle), map[string]string{"rr-scout": "m-fast", "rr-implementer": "", "rr-reviewer": "m-fast"}},
		{"none", tiers(map[core.Tier]string{}, ladder), map[string]string{"rr-scout": "", "rr-implementer": "", "rr-reviewer": ""}},
		{"no runtime entry", nil, map[string]string{"rr-scout": "", "rr-implementer": "", "rr-reviewer": ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := core.SyncInput{Root: "/repo", Home: "/home/test", Policy: fakes.StrictPolicy(), Tiers: c.tiers, Level: core.L1}
			// Poison the policy: a model name only in policy candidates must never be rendered.
			in.Policy.Policy.Models.ByRuntime = map[string]map[core.Tier][]string{Name: {core.TierStrong: {poison}}}
			for _, f := range render(t, in) {
				assert.NotContains(t, string(f.Content), poison, f.Path)
				if !strings.HasPrefix(f.Path, ".claude/agents/") {
					continue
				}
				base := strings.TrimSuffix(strings.TrimPrefix(f.Path, ".claude/agents/"), ".md")
				var got string
				for _, l := range strings.Split(string(f.Content), "\n") {
					if v, ok := strings.CutPrefix(l, "model: "); ok {
						got = v
					}
				}
				assert.Equal(t, c.models[base], got, f.Path)
				if got != "" {
					assert.Contains(t, c.tiers[Name].Models, tierOf(c.tiers[Name].Models, got), f.Path)
				}
			}
		})
	}
}

func tiers(models map[core.Tier]string, ladder map[core.Tier]core.Tier) map[string]core.EffectiveTiers {
	return map[string]core.EffectiveTiers{Name: {Runtime: Name, Models: models, Ladder: ladder}}
}

func without(m map[core.Tier]string, drop ...core.Tier) map[core.Tier]string {
	out := map[core.Tier]string{}
	for k, v := range m {
		out[k] = v
	}
	for _, d := range drop {
		delete(out, d)
	}
	return out
}

func tierOf(m map[core.Tier]string, model string) core.Tier {
	for k, v := range m {
		if v == model {
			return k
		}
	}
	return ""
}

func TestEnforcementValue(t *testing.T) {
	e, err := Adapter{}.Enforcement(context.Background(), "/repo")
	require.NoError(t, err)
	assert.Contains(t, []core.Enforcement{core.EnforcementSandbox, core.EnforcementHookOnly}, e)
	t.Setenv("PATH", t.TempDir())
	e, err = Adapter{}.Enforcement(context.Background(), "/repo")
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementHookOnly, e)
}
