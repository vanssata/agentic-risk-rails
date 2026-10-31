package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Service implements core.PolicyLoader, core.PolicyDiffer and core.PolicyResolver.
type Service struct {
	// Files lists `git ls-files` for glob-set comparison of the working-tree
	// layer. Nil means no files: dropped glob patterns then cannot be verified
	// and count as loosening (fail closed).
	Files func(ctx context.Context) ([]string, error)
}

var (
	_ core.PolicyLoader   = (*Service)(nil)
	_ core.PolicyDiffer   = (*Service)(nil)
	_ core.PolicyResolver = (*Service)(nil)
)

// New returns the policy service to wire into internal/wiring.
func New() *Service { return &Service{} }

// Parse implements core.PolicyLoader.
func (*Service) Parse(b []byte) (core.Policy, error) { return Load(b) }

// Diff implements core.PolicyDiffer.
func (*Service) Diff(base, candidate core.Policy, files []string) (core.Direction, []core.FieldChange, error) {
	return Diff(base, candidate, files)
}

// Resolve implements core.PolicyResolver (DES §3.3): the effective policy is
// the default-branch policy clamped by the user and enterprise ceilings, plus
// the working-tree policy when it does not loosen anything.
func (s *Service) Resolve(ctx context.Context, l core.PolicyLayers) (core.EffectivePolicy, error) {
	if err := ctx.Err(); err != nil {
		return core.EffectivePolicy{}, err
	}
	inForce := projectPolicy(l.DefaultBranch)
	eff := copyPolicy(inForce)

	// Opaque fields: the layer applied last wins, so enterprise goes after user.
	var clamped []string
	for _, c := range []struct {
		name  string
		layer *core.Layer
	}{{"user", l.User}, {"enterprise", l.Enterprise}} {
		if c.layer != nil {
			clamped = append(clamped, tightenTo(&eff, c.layer.Policy, c.name)...)
		}
	}

	var ignored []string
	if l.WorkingTree != nil {
		wt := projectPolicy(l.WorkingTree)
		var files []string
		if s.Files != nil {
			var err error
			if files, err = s.Files(ctx); err != nil {
				return core.EffectivePolicy{}, fmt.Errorf("policy: list files: %w", err)
			}
		}
		d, changes, err := Diff(inForce, wt, files)
		if err != nil {
			return core.EffectivePolicy{}, err
		}
		if d.Loosens() {
			for _, ch := range changes {
				if ch.Direction.Loosens() {
					ignored = append(ignored, ch.Path)
				}
			}
		} else {
			tightenTo(&eff, wt, "working tree")
		}
	}

	sha, err := policySHA(eff)
	if err != nil {
		return core.EffectivePolicy{}, err
	}
	return core.EffectivePolicy{
		Policy:     eff,
		InForce:    inForce,
		PolicySHA:  sha,
		CeilingSHA: ceilingSHA(l.Enterprise, l.User),
		Clamped:    clamped,
		Ignored:    ignored,
	}, nil
}

// projectPolicy returns a defaulted private copy of a project layer (nil = strict defaults).
func projectPolicy(l *core.Layer) core.Policy {
	if l == nil {
		return core.StrictDefaults()
	}
	p := copyPolicy(l.Policy)
	applyDefaults(&p)
	return p
}

func copyPolicy(p core.Policy) core.Policy {
	return deepCopy(reflect.ValueOf(p)).Interface().(core.Policy)
}

// deepCopy copies pointers, slices, maps and structs so that no resolved value
// aliases a caller's layer.
func deepCopy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		n := reflect.New(v.Type().Elem())
		n.Elem().Set(deepCopy(v.Elem()))
		return n
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		n := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			n.Index(i).Set(deepCopy(v.Index(i)))
		}
		return n
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		n := reflect.MakeMapWithSize(v.Type(), v.Len())
		for _, k := range v.MapKeys() {
			n.SetMapIndex(k, deepCopy(v.MapIndex(k)))
		}
		return n
	case reflect.Struct:
		n := reflect.New(v.Type()).Elem()
		for i := range v.NumField() {
			n.Field(i).Set(deepCopy(v.Field(i)))
		}
		return n
	}
	return v
}

// tightenTo merges layer into eff field by field, keeping the strictest value;
// absent layer fields leave eff untouched. It returns the fields it changed.
func tightenTo(eff *core.Policy, layer core.Policy, name string) []string {
	var changed []string
	w := &walker{
		mutate: true,
		leaf: func(r rule, pat, disp string, b, c reflect.Value) error {
			if c.IsZero() {
				return nil
			}
			merged := r.merge(c, b)
			if reflect.DeepEqual(merged.Interface(), b.Interface()) {
				return nil
			}
			b.Set(merged)
			// a user's own model candidates and the ceiling's remote are not clamps
			if pat != "models.by_runtime" && pat != "remote" {
				changed = append(changed, disp+" ("+name+")")
			}
			return nil
		},
		entry: func(disp string, m, key, be, ce reflect.Value) bool {
			switch {
			case !ce.IsValid():
			case !be.IsValid():
				if m.IsNil() {
					m.Set(reflect.MakeMap(m.Type()))
				}
				m.SetMapIndex(key, deepCopy(ce))
				changed = append(changed, disp+" ("+name+")")
			default:
				return true
			}
			return false
		},
	}
	// the walker never fails here: leaf/entry return no error
	_ = w.walk("", "", reflect.ValueOf(eff).Elem(), reflect.ValueOf(&layer).Elem())
	return changed
}

// policySHA hashes the canonical JSON form (struct order, sorted map keys).
func policySHA(p core.Policy) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("policy: canonical form: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ceilingSHA hashes the raw bytes of the ceiling layers; "" when there are none.
func ceilingSHA(layers ...*core.Layer) string {
	h := sha256.New()
	n := 0
	for _, l := range layers {
		if l != nil {
			h.Write(l.Raw)
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
