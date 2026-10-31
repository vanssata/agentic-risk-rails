package policy

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func ptr[T any](v T) *T { return &v }

var treeFiles = []string{
	"riskrails.yaml", ".env", ".env.local", ".github/workflows/ci.yml", "migrations/001.sql", "infra/main.tf",
	"src/Payment/Charge.php", "src/Payment/Gateway/Stripe.php", "src/Security/Voter.php", "src/Util/Str.php",
	"config/app.yaml", "tests/FooTest.php", "composer.json",
}

// strictCase describes a field: starting from `base` (defaults plus prep), `strict`
// makes exactly that field stricter. The reverse change must therefore loosen.
type strictCase struct {
	path   string // key in the direction table
	prep   func(p *core.Policy)
	strict func(p *core.Policy)
}

func (c strictCase) policies() (base, strict core.Policy) {
	base, strict = core.StrictDefaults(), core.StrictDefaults()
	if c.prep != nil {
		c.prep(&base)
		c.prep(&strict)
	}
	c.strict(&strict)
	return base, strict
}

var strictCases = []strictCase{
	{path: "risk.axes.*.declared", strict: func(p *core.Policy) {
		s := p.Risk.Axes[core.AxisScope]
		s.Declared = ptr(true)
		p.Risk.Axes[core.AxisScope] = s
	}},
	{path: "risk.axes.*.bands", strict: func(p *core.Policy) {
		s := p.Risk.Axes[core.AxisScope]
		s.Bands = []int{0, 4}
		p.Risk.Axes[core.AxisScope] = s
	}},
	{path: "risk.axes.*.keywords", strict: func(p *core.Policy) {
		s := p.Risk.Axes[core.AxisBehaviour]
		s.Keywords = append(s.Keywords, "flush")
		p.Risk.Axes[core.AxisBehaviour] = s
	}},
	{path: "risk.axes.*.manifest_floor", strict: func(p *core.Policy) {
		s := p.Risk.Axes[core.AxisNovelty]
		s.ManifestFloor = ptr(2)
		p.Risk.Axes[core.AxisNovelty] = s
	}},
	{path: "risk.axes.*.test_globs", prep: func(p *core.Policy) {
		s := p.Risk.Axes[core.AxisCoverage]
		s.TestGlobs = []string{"tests/**"}
		p.Risk.Axes[core.AxisCoverage] = s
	}, strict: func(p *core.Policy) {
		s := p.Risk.Axes[core.AxisCoverage]
		s.TestGlobs = []string{}
		p.Risk.Axes[core.AxisCoverage] = s
	}},
	{path: "risk.modes.*.min", strict: func(p *core.Policy) {
		m := p.Risk.Modes[core.ModeGuarded]
		m.Min = ptr(2)
		p.Risk.Modes[core.ModeGuarded] = m
	}},
	{path: "risk.modes.*.max", strict: func(p *core.Policy) {
		m := p.Risk.Modes[core.ModeLight]
		m.Max = ptr(1)
		p.Risk.Modes[core.ModeLight] = m
	}},
	{path: "risk.modes.*.trigger", strict: func(p *core.Policy) {
		m := p.Risk.Modes[core.ModeProgramme]
		m.Trigger = append(m.Trigger, "new_service")
		p.Risk.Modes[core.ModeProgramme] = m
	}},
	{path: "risk.hard_floors", strict: func(p *core.Policy) { p.Risk.HardFloors[0].Value = 1 }},
	{path: "risk.hot_paths", strict: func(p *core.Policy) { p.Risk.HotPaths = append(p.Risk.HotPaths, "src/Security/**") }},
	{path: "risk.domain", strict: func(p *core.Policy) { p.Risk.Domain["money"] = []string{"src/Payment/**"} }},
	{path: "risk.reversibility.needs_step", strict: func(p *core.Policy) {
		p.Risk.Reversibility.NeedsStep = append(p.Risk.Reversibility.NeedsStep, "config/**")
	}},
	{path: "risk.reversibility.irreversible", strict: func(p *core.Policy) {
		p.Risk.Reversibility.Irreversible = append(p.Risk.Reversibility.Irreversible, "src/Util/**")
	}},
	{path: "risk.reversibility.irreversible_content", strict: func(p *core.Policy) {
		p.Risk.Reversibility.IrreversibleContent = append(p.Risk.Reversibility.IrreversibleContent, "GRANT ")
	}},
	{path: "risk.rescore.axes", strict: func(p *core.Policy) { p.Risk.Rescore.Axes = append(p.Risk.Rescore.Axes, core.AxisScope) }},
	{path: "risk.rescore.when", strict: func(p *core.Policy) { p.Risk.Rescore.When = append(p.Risk.Rescore.When, "plan") }},
	{path: "risk.policy_file_weight", strict: func(p *core.Policy) { p.Risk.PolicyFileWeight[core.AxisBehaviour] = 3 }},
	{path: "models.tiers_allowed", strict: func(p *core.Policy) { p.Models.TiersAllowed = []core.Tier{core.TierFast, core.TierBalanced} }},
	{path: "models.ladder.never_downgrade_thinking", prep: func(p *core.Policy) { p.Models.Ladder.NeverDowngradeThinking = ptr(false) },
		strict: func(p *core.Policy) { p.Models.Ladder.NeverDowngradeThinking = ptr(true) }},
	{path: "models.effort", strict: func(p *core.Policy) { p.Models.Effort[core.TierFast] = "medium" }},
	{path: "models.budgets", strict: func(p *core.Policy) { p.Models.Budgets[core.ModeLight] = 100_000 }},
	{path: "models.probe.ttl_hours", strict: func(p *core.Policy) { p.Models.Probe.TTLHours = ptr(12) }},
	{path: "autonomy.ceiling", prep: func(p *core.Policy) { p.Autonomy.Ceiling = ptr(core.L2) }, strict: func(p *core.Policy) { p.Autonomy.Ceiling = ptr(core.L1) }},
	{path: "autonomy.by_mode", prep: func(p *core.Policy) { p.Autonomy.ByMode[core.ModeLight] = core.L2 },
		strict: func(p *core.Policy) { p.Autonomy.ByMode[core.ModeLight] = core.L1 }},
	{path: "autonomy.kill_switch.poll_seconds", strict: func(p *core.Policy) { p.Autonomy.KillSwitch.PollSeconds = ptr(30) }},
	{path: "autonomy.unattended.max_wall_minutes", strict: func(p *core.Policy) { p.Autonomy.Unattended.MaxWallMinutes = ptr(60) }},
	{path: "autonomy.unattended.max_tasks_per_day", strict: func(p *core.Policy) { p.Autonomy.Unattended.MaxTasksPerDay = ptr(5) }},
	{path: "enforcement.protected_paths", strict: func(p *core.Policy) {
		p.Enforcement.ProtectedPaths = append(p.Enforcement.ProtectedPaths, "src/Security/**")
	}},
	{path: "enforcement.secret_reads", strict: func(p *core.Policy) { p.Enforcement.SecretReads = append(p.Enforcement.SecretReads, "config/**") }},
	{path: "enforcement.commands.deny", strict: func(p *core.Policy) { p.Enforcement.Commands.Deny = append(p.Enforcement.Commands.Deny, "curl *") }},
	{path: "enforcement.commands.ask", strict: func(p *core.Policy) { p.Enforcement.Commands.Ask = append(p.Enforcement.Commands.Ask, "git commit*") }},
	{path: "enforcement.commands.allow", prep: func(p *core.Policy) { p.Enforcement.Commands.Allow = []string{"git status", "git diff*"} },
		strict: func(p *core.Policy) { p.Enforcement.Commands.Allow = []string{"git status"} }},
	{path: "enforcement.commands.unlisted", prep: func(p *core.Policy) { p.Enforcement.Commands.Unlisted = ptr(core.Ask) },
		strict: func(p *core.Policy) { p.Enforcement.Commands.Unlisted = ptr(core.Deny) }},
	{path: "enforcement.egress.allow", prep: func(p *core.Policy) { p.Enforcement.Egress.Allow = []string{"a.com", "b.com"} },
		strict: func(p *core.Policy) { p.Enforcement.Egress.Allow = []string{"a.com"} }},
	{path: "enforcement.egress.deny_default", prep: func(p *core.Policy) { p.Enforcement.Egress.DenyDefault = ptr(false) },
		strict: func(p *core.Policy) { p.Enforcement.Egress.DenyDefault = ptr(true) }},
	{path: "enforcement.fail_closed", prep: func(p *core.Policy) { p.Enforcement.FailClosed = ptr(false) },
		strict: func(p *core.Policy) { p.Enforcement.FailClosed = ptr(true) }},
	{path: "enforcement.sandbox.required_from", strict: func(p *core.Policy) { p.Enforcement.Sandbox.RequiredFrom = ptr(core.L1) }},
	{path: "enforcement.sandbox.readonly", strict: func(p *core.Policy) {
		p.Enforcement.Sandbox.Readonly = append(p.Enforcement.Sandbox.Readonly, "src/**")
	}},
	{path: "enforcement.sandbox.no_read", strict: func(p *core.Policy) { p.Enforcement.Sandbox.NoRead = append(p.Enforcement.Sandbox.NoRead, "config/**") }},
	{path: "enforcement.sandbox.no_write", strict: func(p *core.Policy) { p.Enforcement.Sandbox.NoWrite = append(p.Enforcement.Sandbox.NoWrite, "src/**") }},
	{path: "verify.full_run_when", strict: func(p *core.Policy) { p.Verify.FullRunWhen = append(p.Verify.FullRunWhen, "config/**") }},
	{path: "verify.nightly_full", prep: func(p *core.Policy) { p.Verify.NightlyFull = ptr(false) }, strict: func(p *core.Policy) { p.Verify.NightlyFull = ptr(true) }},
	{path: "verify.selection_misses_metric", prep: func(p *core.Policy) { p.Verify.SelectionMissesMetric = ptr(false) },
		strict: func(p *core.Policy) { p.Verify.SelectionMissesMetric = ptr(true) }},
	{path: "release.preflight", strict: func(p *core.Policy) { p.Release.Preflight = append(p.Release.Preflight, "composer audit") }},
}

func pathRegexp(path string) *regexp.Regexp {
	return regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(path), `\*`, `[^.]+`) + `(\.|$)`)
}

func TestDiffStrictCasesBothDirections(t *testing.T) {
	for _, c := range strictCases {
		t.Run(c.path, func(t *testing.T) {
			base, strict := c.policies()
			d, ch, err := Diff(base, strict, treeFiles)
			require.NoError(t, err)
			assert.Equal(t, core.Tighten, d, "%v", ch)
			require.NotEmpty(t, ch)
			for _, x := range ch {
				if c.path == "enforcement.secret_reads" && x.Path == "enforcement.sandbox.no_read" {
					continue // sandbox.no_read references $secret_reads
				}
				assert.Regexp(t, pathRegexp(c.path), x.Path)
			}

			d, ch, err = Diff(strict, base, treeFiles)
			require.NoError(t, err)
			assert.Equal(t, core.Loosen, d, "%v", ch)
			assert.True(t, d.Loosens())
			require.NotEmpty(t, ch)
			for _, x := range ch {
				if c.path == "enforcement.secret_reads" && x.Path == "enforcement.sandbox.no_read" {
					continue // sandbox.no_read references $secret_reads
				}
				assert.Regexp(t, pathRegexp(c.path), x.Path)
			}
		})
	}
}

func TestEveryDirectionalFieldHasACase(t *testing.T) {
	tested := map[string]bool{}
	for _, c := range strictCases {
		tested[c.path] = true
	}
	for path, r := range directions {
		if reflect.ValueOf(r.cmp).Pointer() == reflect.ValueOf(opaqueRule.cmp).Pointer() {
			continue
		}
		// compare closures by identity of the table entry: opaque entries share opaqueRule
		assert.True(t, tested[path], "no strict case for %s", path)
	}
}

func TestOpaqueFieldsAnyChangeLoosens(t *testing.T) {
	muts := map[string]func(p *core.Policy){
		"remote":                 func(p *core.Policy) { p.Remote = "a/b" },
		"schema":                 func(p *core.Policy) { p.Schema = 2 },
		"project.name":           func(p *core.Policy) { p.Project.Name = "x" },
		"project.stack":          func(p *core.Policy) { p.Project.Stack = []string{"go"} },
		"project.default_branch": func(p *core.Policy) { p.Project.DefaultBranch = "dev" },
		"risk.axes.*.measured": func(p *core.Policy) {
			s := p.Risk.Axes[core.AxisScope]
			s.Measured = "paths"
			p.Risk.Axes[core.AxisScope] = s
		},
		"risk.rescore.direction":             func(p *core.Policy) { p.Risk.Rescore.Direction = "down" },
		"models.by_runtime":                  func(p *core.Policy) { p.Models.ByRuntime["claude"] = map[core.Tier][]string{core.TierFast: {"haiku"}} },
		"models.ladder.missing":              func(p *core.Policy) { p.Models.Ladder.Missing[core.TierFast] = core.TierStrong },
		"models.ladder.on_error":             func(p *core.Policy) { p.Models.Ladder.OnError["rate_limit"] = "fail" },
		"models.probe.on_4xx":                func(p *core.Policy) { p.Models.Probe.On4xx = "ignore" },
		"models.probe.cache":                 func(p *core.Policy) { p.Models.Probe.Cache = "/tmp/x" },
		"autonomy.output":                    func(p *core.Policy) { p.Autonomy.Output = "merge" },
		"autonomy.kill_switch.remote_file":   func(p *core.Policy) { p.Autonomy.KillSwitch.RemoteFile = ".rr/OTHER" },
		"autonomy.kill_switch.on_read_error": func(p *core.Policy) { p.Autonomy.KillSwitch.OnReadError = "continue" },
		"autonomy.unattended.container":      func(p *core.Policy) { p.Autonomy.Unattended.Container = "optional" },
		"enforcement.commands.parser":        func(p *core.Policy) { p.Enforcement.Commands.Parser = "regex" },
		"verify.adapters": func(p *core.Policy) {
			p.Verify.Adapters = []core.VerifyAdapterSpec{{Name: "phpunit", Cmd: "php bin/phpunit"}}
		},
		"verify.suite_budget":         func(p *core.Policy) { p.Verify.SuiteBudget = ptr(1) },
		"release.ecosystem":           func(p *core.Policy) { p.Release.Ecosystem = "npm" },
		"release.channel":             func(p *core.Policy) { p.Release.Channel = "branch" },
		"release.publish_via":         func(p *core.Policy) { p.Release.PublishVia = "token" },
		"research.by_mode":            func(p *core.Policy) { p.Research.ByMode[core.ModeLight] = []string{"code"} },
		"research.tier":               func(p *core.Policy) { p.Research.Tier = core.TierStrong },
		"research.budget_per_scout":   func(p *core.Policy) { p.Research.BudgetPerScout = ptr(core.TokenCount(1)) },
		"research.cache.key":          func(p *core.Policy) { p.Research.Cache.Key = []string{"x"} },
		"research.cache.dir":          func(p *core.Policy) { p.Research.Cache.Dir = "/x" },
		"research.tech_docs.sources":  func(p *core.Policy) { p.Research.TechDocs.Sources = []string{"x"} },
		"research.tech_docs.pin_from": func(p *core.Policy) { p.Research.TechDocs.PinFrom = "go.sum" },
		"research.tech_docs.context7": func(p *core.Policy) { p.Research.TechDocs.Context7 = ptr(true) },
	}
	for path, r := range directions {
		if reflect.ValueOf(r.cmp).Pointer() != reflect.ValueOf(opaqueRule.cmp).Pointer() {
			continue
		}
		mut, ok := muts[path]
		require.True(t, ok, "no opaque mutation for %s", path)
		t.Run(path, func(t *testing.T) {
			base, cand := core.StrictDefaults(), core.StrictDefaults()
			mut(&cand)
			for _, pair := range [][2]core.Policy{{base, cand}, {cand, base}} {
				d, ch, err := Diff(pair[0], pair[1], treeFiles)
				require.NoError(t, err)
				assert.Equal(t, core.Loosen, d, "%v", ch)
			}
		})
	}
}

func TestDirectionTableCoversEveryPolicyField(t *testing.T) {
	leaves := leafPaths(reflect.TypeOf(core.Policy{}), "")
	require.NotEmpty(t, leaves)
	seen := map[string]bool{}
	for _, p := range leaves {
		seen[p] = true
		_, ok := directions[p]
		assert.True(t, ok, "core.Policy field %q has no entry in the direction table", p)
	}
	for p := range directions {
		assert.True(t, seen[p], "direction table entry %q matches no core.Policy field", p)
	}
}

func TestDiffEqual(t *testing.T) {
	d, ch, err := Diff(core.StrictDefaults(), core.StrictDefaults(), treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Equal, d)
	assert.Empty(t, ch)
}

func TestNarrowingPaymentGlobIsLoosen(t *testing.T) {
	base := core.StrictDefaults()
	base.Risk.HotPaths = []string{"src/Payment/**"}
	cand := core.StrictDefaults()
	cand.Risk.HotPaths = []string{"src/Payment/*.php"}

	d, ch, err := Diff(base, cand, treeFiles) // src/Payment/Gateway/Stripe.php is nested
	require.NoError(t, err)
	assert.Equal(t, core.Loosen, d)
	require.Len(t, ch, 1)
	assert.Equal(t, "risk.hot_paths", ch[0].Path)

	// narrowing is LOOSEN even when it matches the same files today
	flat := []string{"src/Payment/Charge.php"}
	d, _, err = Diff(base, cand, flat)
	require.NoError(t, err)
	assert.Equal(t, core.Loosen, d)

	// widening is fine
	d, _, err = Diff(cand, base, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Tighten, d)
}

func TestDroppedPatternWithoutFilesCannotBeVerified(t *testing.T) {
	base := core.StrictDefaults()
	cand := core.StrictDefaults()
	cand.Risk.Reversibility.Irreversible = []string{"migrations/**"} // infra/** dropped
	d, _, err := Diff(base, cand, []string{"src/a.php"})
	require.NoError(t, err)
	assert.Equal(t, core.Loosen, d)
	d, _, err = Diff(base, cand, nil)
	require.NoError(t, err)
	assert.Equal(t, core.Loosen, d)
}

func TestMovingEntryBetweenListsIsDecidedPerList(t *testing.T) {
	base := core.StrictDefaults()
	base.Enforcement.Commands.Allow = []string{"git status"}
	cand := core.StrictDefaults()
	cand.Enforcement.Commands.Allow = []string{}
	cand.Enforcement.Commands.Ask = []string{"git status"}
	d, _, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Tighten, d)

	// the other way round: ask -> allow
	d, _, err = Diff(cand, base, treeFiles)
	require.NoError(t, err)
	assert.True(t, d.Loosens())
}

func TestMixedLoosens(t *testing.T) {
	base := core.StrictDefaults()
	cand := core.StrictDefaults()
	cand.Autonomy.Unattended.MaxTasksPerDay = ptr(5)            // tighten
	cand.Enforcement.Commands.Allow = []string{"composer test"} // loosen
	d, ch, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Mixed, d)
	assert.True(t, d.Loosens())
	assert.Len(t, ch, 2)
}

func TestSandboxReferencesAreExpanded(t *testing.T) {
	base := core.StrictDefaults() // no_read: $secret_reads, ...
	cand := core.StrictDefaults()
	cand.Enforcement.Sandbox.NoRead = []string{"~/.config/riskrails/**", "~/.cache/riskrails/**", ".env*", "~/.ssh/**", "~/.aws/**"}
	d, _, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Equal, d, "literal list equal to the expanded reference")

	cand.Enforcement.Sandbox.NoRead = []string{"~/.config/riskrails/**", "~/.cache/riskrails/**"}
	d, _, err = Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.True(t, d.Loosens())
}

func TestMapEntriesAddedOrRemoved(t *testing.T) {
	base := core.StrictDefaults()
	cand := core.StrictDefaults()
	delete(cand.Risk.Axes, core.AxisNovelty)
	d, ch, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Loosen, d)
	assert.Equal(t, "risk.axes.novelty", ch[0].Path)

	d, _, err = Diff(cand, base, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Tighten, d)

	delete(cand.Models.Budgets, core.ModeFull)
	d, _, err = Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.True(t, d.Loosens())
}

func TestNarrowingMatchingSameFilesIsLoosen(t *testing.T) {
	for name, tc := range map[string]struct {
		base, cand []string
		files      []string
	}{
		"single file":      {[]string{"migrations/**"}, []string{"migrations/001.sql"}, []string{"migrations/001.sql"}},
		"split wildcard":   {[]string{"src/Pay*/**"}, []string{"src/Payment/**", "src/Payroll/**"}, []string{"src/Payment/a.php", "src/Payroll/b.php"}},
		"star to explicit": {[]string{"src/**"}, []string{"src/Payment/**", "src/Util/**"}, []string{"src/Payment/a.php", "src/Util/b.php"}},
	} {
		t.Run(name, func(t *testing.T) {
			base, cand := core.StrictDefaults(), core.StrictDefaults()
			base.Risk.HotPaths, cand.Risk.HotPaths = tc.base, tc.cand
			d, _, err := Diff(base, cand, tc.files)
			require.NoError(t, err)
			assert.True(t, d.Loosens())
		})
	}
	// broader cover is fine
	base, cand := core.StrictDefaults(), core.StrictDefaults()
	base.Risk.HotPaths, cand.Risk.HotPaths = []string{"src/Payment/**"}, []string{"src/**"}
	d, _, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Tighten, d)
	cand.Risk.HotPaths = []string{"**"}
	d, _, err = Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Tighten, d)
}

func TestAllowEntrySubsumedByBaseAddsNothing(t *testing.T) {
	base, cand := core.StrictDefaults(), core.StrictDefaults()
	base.Enforcement.Commands.Allow = []string{"git diff*"}
	cand.Enforcement.Commands.Allow = []string{"git diff*", "git diff --stat"}
	d, _, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Equal, d)

	cand.Enforcement.Commands.Allow = []string{"git diff*", "git push"}
	d, _, err = Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.True(t, d.Loosens())
}

func TestHardFloorFullIrreversibleToProgrammeLoosens(t *testing.T) {
	base, cand := core.StrictDefaults(), core.StrictDefaults()
	cand.Risk.HardFloors[2].Mode = core.ModeProgramme // was full_irreversible
	d, _, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.True(t, d.Loosens())
	d, _, err = Diff(cand, base, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Tighten, d)
}

func TestHardFloorCoverage(t *testing.T) {
	base := core.StrictDefaults()
	cand := core.StrictDefaults()
	cand.Risk.HardFloors = cand.Risk.HardFloors[:2] // drop the both-axes floor
	d, _, err := Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.Equal(t, core.Loosen, d)

	cand = core.StrictDefaults()
	cand.Risk.HardFloors[1].Review = "" // drop the security review requirement
	d, _, err = Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.True(t, d.Loosens())

	cand = core.StrictDefaults()
	cand.Risk.HardFloors[0].Mode = core.ModeLight // weaker mode
	d, _, err = Diff(base, cand, treeFiles)
	require.NoError(t, err)
	assert.True(t, d.Loosens())
}
