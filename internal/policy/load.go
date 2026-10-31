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

	"gopkg.in/yaml.v3"

	"github.com/vanssata/agentic-risk-rails/internal/core"
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
	return errors.Join(errs...)
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
