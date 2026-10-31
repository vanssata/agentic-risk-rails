// Package journal: event type registry. Modules declare their events in
// internal/<module>/events.go with MustRegister in init(). The journal
// rejects unregistered types on Append (implemented in wave 1, W1-B).
package journal

import (
	"fmt"
	"sort"
	"sync"
)

// Spec describes one event type.
type Spec struct {
	Type     string
	Module   string
	Required bool // must appear in every closed task (checked by rr doctor)
	Doc      string
}

var (
	regMu sync.RWMutex
	reg   = map[string]Spec{}
)

// MustRegister adds an event type; duplicates panic at init time.
func MustRegister(specs ...Spec) {
	regMu.Lock()
	defer regMu.Unlock()
	for _, s := range specs {
		if s.Type == "" || s.Module == "" {
			panic("journal: event spec needs Type and Module")
		}
		if old, ok := reg[s.Type]; ok {
			panic(fmt.Sprintf("journal: event %q registered by %s and %s", s.Type, old.Module, s.Module))
		}
		reg[s.Type] = s
	}
}

// Lookup returns the spec of a registered event type.
func Lookup(typ string) (Spec, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	s, ok := reg[typ]
	return s, ok
}

// All returns every registered spec sorted by type.
func All() []Spec {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Spec, 0, len(reg))
	for _, s := range reg {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// Required returns the types every closed task must contain.
func Required() []string {
	var out []string
	for _, s := range All() {
		if s.Required {
			out = append(out, s.Type)
		}
	}
	return out
}
