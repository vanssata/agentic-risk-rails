package triage

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func bp(b bool) *bool { return &b }
func ip(i int) *int   { return &i }

// sq1Policy is claude-agentic's weight.json expressed in the DES 3.2 schema.
// Its "hints" have no DES field: auth/pipeline paths are folded into the globs.
func sq1Policy() core.Policy {
	p := core.StrictDefaults()
	p.Risk.Axes = map[core.Axis]core.AxisSpec{
		core.AxisScope:         {Measured: "refs", Bands: []int{0, 5}},
		core.AxisBehaviour:     {Declared: bp(true), Keywords: []string{"workflow", "transition", "state machine", "messenger", "queue", "async", "transaction"}},
		core.AxisReversibility: {Measured: "paths"},
		core.AxisDomain:        {Measured: "paths", Declared: bp(true)},
		core.AxisNovelty:       {Declared: bp(true), ManifestFloor: ip(1)},
		core.AxisCoverage: {Measured: "tests", TestGlobs: []string{
			"tests/**", "spec/**", "**/*Test.php", "**/*.test.*", "**/*.spec.*", "**/test_*.py"}},
	}
	p.Risk.HotPaths = []string{"hooks/**", "src/Shared/**"}
	p.Risk.Domain = map[string][]string{
		"money":            {"**/Payment/**", "**/Tax/**", "**/Invoice/**", "**/Security/**", "**/account/**", "**/secret*"},
		"customer_visible": {"**/templates/**", "**/Shop/**", "**/Resources/views/**"},
	}
	p.Risk.Reversibility = core.ReversibilitySpec{
		NeedsStep:           []string{"**/migrations/**", "**/Migrations/**", "config/**", "k8s/**", "**/env/**"},
		Irreversible:        []string{"**/prod/**", "**/production/**", "deploy/**", "skills/project-update/migrations/**"},
		IrreversibleContent: []string{"DROP ", "TRUNCATE", "DELETE FROM", "ALTER .* DROP", "RENAME"},
	}
	return p
}

type ax = map[core.Axis]int

// order: scope, behaviour, reversibility, domain, novelty, coverage
func axes(s, b, r, d, n, c int) ax {
	return ax{core.AxisScope: s, core.AxisBehaviour: b, core.AxisReversibility: r, core.AxisDomain: d, core.AxisNovelty: n, core.AxisCoverage: c}
}

func decl(kv ...any) ax {
	m := ax{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i].(core.Axis)] = kv[i+1].(int)
	}
	return m
}

const (
	sc, bh, rv, dm, nv, cv = core.AxisScope, core.AxisBehaviour, core.AxisReversibility, core.AxisDomain, core.AxisNovelty, core.AxisCoverage
)

// TestSQ1 is TestSQ1 of claude-agentic/tests/test_weight.py: input -> axes -> mode.
func TestSQ1(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want ax
		mode core.Mode
	}{
		{"font in login template",
			Input{Files: []string{"themes/shop/templates/login.html.twig"}, Refs: map[string]int{"themes/shop/templates/login.html.twig": 0},
				Declared: decl(bh, 0, nv, 0)},
			axes(0, 0, 0, 1, 0, 0), core.ModeLight},
		{"odoo vat module",
			Input{Files: []string{"addons/vat/account/vat_rules.py", "addons/vat/account/vat_report.py"},
				Refs:     map[string]int{"addons/vat/account/vat_rules.py": 6, "addons/vat/account/vat_report.py": 0},
				Tree:     []string{"tests/test_vat_rules.py"},
				Declared: decl(bh, 1, nv, 1)},
			axes(2, 1, 0, 2, 1, 1), core.ModeFull},
		{"enum fixture in migrations data",
			Input{Files: []string{"src/Acme/EnumBundle/Migrations/Data/ORM/LoadEnumData.php", "src/Acme/EnumBundle/Entity/EnumValue.php"},
				Refs: map[string]int{"src/Acme/EnumBundle/Migrations/Data/ORM/LoadEnumData.php": 2, "src/Acme/EnumBundle/Entity/EnumValue.php": 2},
				Tree: []string{"tests/Unit/EnumValueTest.php"}, Declared: decl(bh, 1, dm, 1, nv, 0)},
			axes(1, 1, 1, 1, 0, 1), core.ModeGuarded},
		{"generated ddl in a test fixture",
			Input{Files: []string{"tests/fixtures/ddl/schema.sql"}, Refs: map[string]int{"tests/fixtures/ddl/schema.sql": 0},
				Content: map[string]string{"tests/fixtures/ddl/schema.sql": "CREATE TABLE t (id int);\nDROP TABLE t;\n"}},
			axes(0, 0, 0, 0, 0, 0), core.ModeLight},
		{"regex fix in a hot guard",
			Input{Files: []string{"hooks/ai-path-guard.sh"}, Refs: map[string]int{"hooks/ai-path-guard.sh": 0},
				Tree: []string{"tests/test-ai-path-guard.sh"}, Declared: decl(bh, 1, dm, 0, nv, 0)},
			axes(2, 1, 0, 0, 0, 0), core.ModeGuarded},
		{"migration deleting user files",
			Input{Files: []string{"skills/project-update/migrations/0006_retire.py", "skills/project-update/update.py"},
				Refs: map[string]int{"skills/project-update/migrations/0006_retire.py": 6, "skills/project-update/update.py": 0},
				Tree: []string{"tests/test-project-update.sh"}, Declared: decl(bh, 2, dm, 0, nv, 1)},
			axes(2, 2, 2, 0, 1, 1), core.ModeFull},
		{"argocd dev manifest",
			Input{Files: []string{"k8s/apps/env/dev/values.yaml"}, Refs: map[string]int{"k8s/apps/env/dev/values.yaml": 1},
				Declared: decl(bh, 1, dm, 0, nv, 0)},
			axes(1, 1, 1, 0, 0, 0), core.ModeGuarded},
		{"argocd prod manifest and secret",
			Input{Files: []string{"k8s/apps/env/prod/values.yaml", "k8s/apps/env/prod/secret-db.yaml"},
				Refs: map[string]int{"k8s/apps/env/prod/values.yaml": 1, "k8s/apps/env/prod/secret-db.yaml": 0}, Declared: decl(bh, 1, nv, 0)},
			axes(1, 1, 2, 2, 0, 0), core.ModeFullIrreversible},
		{"project CLAUDE.md",
			Input{Files: []string{"CLAUDE.md"}, Refs: map[string]int{"CLAUDE.md": 1}, Declared: decl(bh, 1, dm, 0, nv, 0)},
			axes(1, 1, 0, 0, 0, 0), core.ModeLight},
		{"product editor feature",
			Input{Files: []string{"src/Entity/Product.php", "migrations/Version20261025.php", "assets/editor/ProductScreen.js", "templates/product/edit.html.twig"},
				Refs: map[string]int{"src/Entity/Product.php": 2, "migrations/Version20261025.php": 0, "templates/product/edit.html.twig": 1},
				Tree: []string{"tests/Entity/ProductTest.php"}, Declared: decl(bh, 1, nv, 1)},
			axes(1, 1, 1, 1, 1, 1), core.ModeGuarded},
		{"product editor feature, new mechanism, no tests",
			Input{Files: []string{"src/Entity/Product.php", "migrations/Version20261025.php", "assets/editor/ProductScreen.js", "templates/product/edit.html.twig"},
				Refs: map[string]int{"src/Entity/Product.php": 2, "migrations/Version20261025.php": 0, "templates/product/edit.html.twig": 1},
				Declared: decl(bh, 2, nv, 2)},
			axes(1, 2, 1, 1, 2, 2), core.ModeFull},
		{"learning workbench feature",
			Input{Files: []string{"workbench/lessons.py", "workbench/grading.py"},
				Refs: map[string]int{"workbench/lessons.py": 2, "workbench/grading.py": 0},
				Tree: []string{"tests/test_lessons.py"}, Declared: decl(bh, 1, nv, 1, dm, 0)},
			axes(1, 1, 0, 0, 1, 1), core.ModeGuarded},
		{"three lines in payment",
			Input{Files: []string{"src/Payment/Refund.php"}, Refs: map[string]int{"src/Payment/Refund.php": 0}},
			axes(0, 1, 0, 2, 1, 2), core.ModeFull},
		{"test-only change",
			Input{Files: []string{"tests/test_messages.py"}, Refs: map[string]int{"tests/test_messages.py": 0}},
			axes(0, 0, 0, 0, 0, 0), core.ModeLight},
		{"message text change",
			Input{Files: []string{"translations/messages.en.yaml"}, Refs: map[string]int{"translations/messages.en.yaml": 0},
				Declared: decl(bh, 0, dm, 0, nv, 0)},
			axes(0, 0, 0, 0, 0, 0), core.ModeLight},
	}
	pol := sq1Policy()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := Score(pol, c.in)
			assert.Equal(t, c.want, w.Axes, w.Reasons)
			assert.Equal(t, c.mode, w.Mode, w.Reasons)
		})
	}
}

func TestDeclaredOnlyRaises(t *testing.T) {
	pol := sq1Policy()
	in := Input{Files: []string{"src/Payment/Refund.php"}, Refs: map[string]int{"src/Payment/Refund.php": 0}, Declared: decl(dm, 0, bh, 2)}
	w := Score(pol, in)
	assert.Equal(t, 2, w.Axes[dm], "declaration below the measurement is replaced")
	assert.Equal(t, 2, w.Axes[bh])
}

func TestBehaviourKeywordFloorAndManifest(t *testing.T) {
	pol := sq1Policy()
	w := Score(pol, Input{Files: []string{"composer.json"}, Refs: map[string]int{"composer.json": 0}, Goal: "make the Queue async",
		Declared: decl(bh, 0, nv, 0)})
	assert.Equal(t, 1, w.Axes[bh], "keyword in the goal is a floor")
	assert.Equal(t, 1, w.Axes[nv], "manifest floor beats a declared 0")
}

func TestIrreversibleContentNeedsStepFile(t *testing.T) {
	pol := sq1Policy()
	in := Input{Files: []string{"config/db.php"}, Content: map[string]string{"config/db.php": "x DELETE FROM users"}}
	assert.Equal(t, 2, Score(pol, in).Axes[rv])
	in.Files, in.Content = []string{"src/a.php"}, map[string]string{"src/a.php": "DELETE FROM users"}
	assert.Equal(t, 0, Score(pol, in).Axes[rv], "content counts only in needs_step/irreversible files")
}

func TestModes(t *testing.T) {
	pol := sq1Policy()
	pol.Risk.Modes[core.ModeProgramme] = core.ModeBand{Trigger: []string{"spec", ">1 session", "files > 2"}}
	base := Input{Files: []string{"a.txt"}, Declared: decl(bh, 0, dm, 0, nv, 0)}
	assert.Equal(t, core.ModeLight, Score(pol, base).Mode)
	for _, in := range []Input{
		{Files: base.Files, Declared: base.Declared, Spec: true},
		{Files: base.Files, Declared: base.Declared, Sessions: 2},
		{Files: []string{"a", "b", "c"}, Declared: base.Declared},
	} {
		assert.Equal(t, core.ModeProgramme, Score(pol, in).Mode)
	}
	pol.Risk.Modes[core.ModeProgramme] = core.ModeBand{Trigger: []string{"weekly"}}
	assert.Equal(t, core.ModeProgramme, Score(pol, base).Mode, "unknown trigger errs upward")
}

func TestPolicyFileWeight(t *testing.T) {
	pol := sq1Policy()
	w := Score(pol, Input{Files: []string{"riskrails.yaml"}, Declared: decl(bh, 0, dm, 0, nv, 0)})
	assert.Equal(t, core.ModeFull, w.Mode)
	assert.Equal(t, 2, w.Axes[dm])
}

func TestAmendRecomputesAllSix(t *testing.T) {
	pol := sq1Policy()
	prev := Score(pol, Input{Files: []string{"workbench/a.py"}, Refs: map[string]int{"workbench/a.py": 0}, Tree: []string{"tests/test_a.py"},
		Declared: decl(bh, 0, dm, 0, nv, 0)})
	require.Equal(t, core.ModeLight, prev.Mode)
	got := Amend(pol, prev, Input{Files: []string{"workbench/a.py", "composer.json", "src/Payment/x.php"},
		Refs: map[string]int{"workbench/a.py": 9}, Tree: []string{"tests/test_a.py"}, Declared: decl(bh, 0, dm, 0, nv, 0)})
	assert.Equal(t, 2, got.Axes[sc], "amend raises scope too")
	assert.Equal(t, 1, got.Axes[nv])
	assert.Equal(t, core.ModeFull, got.Mode)
	// Rescore leaves scope alone (rescore.axes = reversibility, domain).
	r := Rescore(pol, prev, Input{Files: []string{"workbench/a.py"}, Refs: map[string]int{"workbench/a.py": 9}, Tree: []string{"tests/test_a.py"},
		Declared: decl(bh, 0, dm, 0, nv, 0)})
	assert.Equal(t, 0, r.Axes[sc])
}

// Property: Rescore/Amend never lower an axis or the mode, whatever the diff.
func TestRescoreNeverLowers(t *testing.T) {
	pol := sq1Policy()
	pool := []string{"src/Payment/a.php", "migrations/V1.php", "config/x.yml", "composer.json", "tests/aTest.php",
		"README.md", "templates/x.twig", "hooks/h.sh", "k8s/apps/env/prod/v.yaml", "riskrails.yaml", "src/b.php"}
	text := []string{"", "DROP TABLE x", "DELETE FROM t", "queue", "plain"}
	rng := rand.New(rand.NewSource(1))
	gen := func() Input {
		in := Input{Refs: map[string]int{}, Content: map[string]string{}, Declared: ax{}, Spec: rng.Intn(8) == 0, Sessions: rng.Intn(3)}
		for _, f := range pool {
			if rng.Intn(3) == 0 {
				in.Files = append(in.Files, f)
				in.Content[f] = text[rng.Intn(len(text))]
				if rng.Intn(2) == 0 {
					in.Refs[f] = rng.Intn(9)
				}
			}
		}
		for _, a := range core.Axes {
			if rng.Intn(3) == 0 {
				in.Declared[a] = rng.Intn(3)
			}
		}
		return in
	}
	for i := 0; i < 2000; i++ {
		prev := Score(pol, gen())
		for _, next := range []core.Weight{Rescore(pol, prev, gen()), Amend(pol, prev, gen())} {
			require.GreaterOrEqual(t, next.Mode.Rank(), prev.Mode.Rank())
			for _, a := range core.Axes {
				require.GreaterOrEqual(t, next.Axes[a], prev.Axes[a])
			}
		}
	}
}
