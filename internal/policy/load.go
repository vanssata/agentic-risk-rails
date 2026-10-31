// Package policy loads riskrails.yaml, compares policies deterministically
// (TIGHTEN/LOOSEN, no model involved) and resolves the layers into the
// effective policy (DES §3).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
)

// Load strictly parses a project riskrails.yaml and fills every absent field
// from core.StrictDefaults(). An empty file equals StrictDefaults().
func Load(b []byte) (core.Policy, error) {
	p, err := decode(b)
	if err != nil {
		return core.Policy{}, err
	}
	if err := validate(&p, false); err != nil {
		return core.Policy{}, err
	}
	applyDefaults(&p)
	return p, nil
}

// LoadCeiling strictly parses a ceiling layer: no defaults (absent = no
// constraint) and the ceiling-only `remote` is allowed.
func LoadCeiling(b []byte) (core.Policy, error) {
	p, err := decode(b)
	if err != nil {
		return core.Policy{}, err
	}
	if err := validate(&p, true); err != nil {
		return core.Policy{}, err
	}
	return p, nil
}

func decode(b []byte) (core.Policy, error) {
	var p core.Policy
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return core.Policy{}, fmt.Errorf("policy: %w", err)
	}
	var extra yaml.Node
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return core.Policy{}, errors.New("policy: more than one YAML document")
	}
	return p, nil
}

// validate rejects values the schema forbids. Empty values are "absent" and
// pass: a project gets the (valid) default, a ceiling leaves it unconstrained.
func validate(p *core.Policy, ceiling bool) error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("policy: "+format, a...)) }

	if !ceiling && p.Remote != "" {
		bad("remote is ceiling-only and not allowed in riskrails.yaml")
	}
	if p.Schema != 0 && p.Schema != 1 {
		bad("schema must be 1, got %d", p.Schema)
	}
	if fc := p.Enforcement.FailClosed; fc != nil && !*fc {
		bad("enforcement.fail_closed must be true")
	}
	for t, e := range p.Models.Effort {
		if !slices.Contains([]string{"low", "medium", "high"}, e) {
			bad("models.effort.%s must be low|medium|high, got %q", t, e)
		}
	}
	for a, s := range p.Risk.Axes {
		if !slices.Contains([]string{"", "refs", "paths", "tests"}, s.Measured) {
			bad("risk.axes.%s.measured must be refs|paths|tests, got %q", a, s.Measured)
		}
	}
	only := func(path, got, want string) {
		if got != "" && got != want {
			bad("%s must be %q, got %q", path, want, got)
		}
	}
	only("risk.rescore.direction", p.Risk.Rescore.Direction, "up_only")
	only("autonomy.output", p.Autonomy.Output, "pr_only")
	only("enforcement.commands.parser", p.Enforcement.Commands.Parser, "ast")
	only("autonomy.kill_switch.on_read_error", p.Autonomy.KillSwitch.OnReadError, "halt")
	validateNumbers(p, bad)
	validateGlobs(p, bad)
	return errors.Join(errs...)
}

func validateNumbers(p *core.Policy, bad func(string, ...any)) {
	atLeast1 := func(path string, v *int) {
		if v != nil && *v < 1 {
			bad("%s must be >= 1, got %d", path, *v)
		}
	}
	atLeast1("autonomy.unattended.max_wall_minutes", p.Autonomy.Unattended.MaxWallMinutes)
	atLeast1("autonomy.unattended.max_tasks_per_day", p.Autonomy.Unattended.MaxTasksPerDay)
	atLeast1("autonomy.kill_switch.poll_seconds", p.Autonomy.KillSwitch.PollSeconds)
	atLeast1("models.probe.ttl_hours", p.Models.Probe.TTLHours)
	atLeast1("verify.suite_budget", p.Verify.SuiteBudget)
	for m, b := range p.Models.Budgets {
		if b < 1 {
			bad("models.budgets.%s must be >= 1, got %d", m, b)
		}
	}
	if b := p.Research.BudgetPerScout; b != nil && *b < 1 {
		bad("research.budget_per_scout must be >= 1, got %d", *b)
	}
	for a, s := range p.Risk.Axes {
		for i, v := range s.Bands {
			if v < 0 || (i > 0 && v <= s.Bands[i-1]) {
				bad("risk.axes.%s.bands must be non-negative and strictly increasing, got %v", a, s.Bands)
				break
			}
		}
	}
	for m, b := range p.Risk.Modes {
		if (b.Min != nil && *b.Min < 0) || (b.Max != nil && *b.Max < 0) || (b.Min != nil && b.Max != nil && *b.Min > *b.Max) {
			bad("risk.modes.%s needs 0 <= min <= max", m)
		}
	}
}

// validateGlobs rejects syntactically invalid path patterns: an invalid
// deny pattern would silently match nothing.
func validateGlobs(p *core.Policy, bad func(string, ...any)) {
	check := func(path string, list []string) {
		for _, g := range list {
			if !strings.HasPrefix(g, "$") && !globs.Valid(g) {
				bad("%s: invalid glob %q", path, g)
			}
		}
	}
	check("risk.hot_paths", p.Risk.HotPaths)
	for k, l := range p.Risk.Domain {
		check("risk.domain."+k, l)
	}
	check("risk.reversibility.needs_step", p.Risk.Reversibility.NeedsStep)
	check("risk.reversibility.irreversible", p.Risk.Reversibility.Irreversible)
	check("enforcement.protected_paths", p.Enforcement.ProtectedPaths)
	check("enforcement.secret_reads", p.Enforcement.SecretReads)
	check("enforcement.sandbox.readonly", p.Enforcement.Sandbox.Readonly)
	check("enforcement.sandbox.no_read", p.Enforcement.Sandbox.NoRead)
	check("enforcement.sandbox.no_write", p.Enforcement.Sandbox.NoWrite)
	for a, s := range p.Risk.Axes {
		check("risk.axes."+string(a)+".test_globs", s.TestGlobs)
	}
}

// applyDefaults fills every absent field of p from core.StrictDefaults().
func applyDefaults(p *core.Policy) {
	def := core.StrictDefaults()
	fill(reflect.ValueOf(p).Elem(), reflect.ValueOf(&def).Elem())
}

// fill copies def into dst wherever dst is absent: nil pointer/slice/map,
// zero scalar, and — for maps — each missing key. Map entries are atomic: a
// present axis or mode is never completed attribute by attribute.
func fill(dst, def reflect.Value) {
	switch dst.Kind() {
	case reflect.Struct:
		for i := range dst.NumField() {
			fill(dst.Field(i), def.Field(i))
		}
	case reflect.Map:
		if dst.IsNil() {
			dst.Set(def)
			return
		}
		for _, k := range def.MapKeys() {
			if !dst.MapIndex(k).IsValid() {
				dst.SetMapIndex(k, def.MapIndex(k))
			}
		}
	default: // pointer, slice, scalar
		if dst.IsZero() {
			dst.Set(def)
		}
	}
}
