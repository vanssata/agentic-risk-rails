package core_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func TestUnknownDecisionIsStrictest(t *testing.T) {
	assert.Equal(t, core.Deny, core.Stricter("", core.Allow))
	assert.Equal(t, core.Deny, core.Stricter(core.Allow, "bogus"))
	assert.Greater(t, core.Decision("").Rank(), core.Deny.Rank()-1)
}

func TestLoosens(t *testing.T) {
	for d, want := range map[core.Direction]bool{
		core.Equal: false, core.Tighten: false, core.Loosen: true, core.Mixed: true, "": true, "garbage": true,
	} {
		assert.Equal(t, want, d.Loosens(), string(d))
	}
}

func TestRefusal(t *testing.T) {
	var err error = &core.Refusal{Code: "NO_TIER"}
	var r *core.Refusal
	assert.True(t, errors.As(err, &r))
	assert.Equal(t, "REFUSE {NO_TIER}", err.Error())
}

// EffectivePolicy invariant: StrictDefaults has no nil setting pointers or maps.
func TestStrictDefaultsFullyDefaulted(t *testing.T) {
	var walk func(path string, v reflect.Value)
	walk = func(path string, v reflect.Value) {
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() {
				if path != ".Policy.Remote" {
					t.Errorf("nil pointer at %s", path)
				}
				return
			}
			walk(path, v.Elem())
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				walk(path+"."+v.Type().Field(i).Name, v.Field(i))
			}
		case reflect.Map:
			// Entries of axes/modes may leave optional attributes nil (= not applicable).
			if v.IsNil() {
				t.Errorf("nil map at %s", path)
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				walk(path, v.Index(i))
			}
		}
	}
	walk(".Policy", reflect.ValueOf(core.StrictDefaults()))
}
