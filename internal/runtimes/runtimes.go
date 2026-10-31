// Package runtimes is the registry of RuntimeAdapters. Each adapter package
// calls Register in init() and is linked into rr by cmd/rr/link_<name>.go.
package runtimes

import (
	"fmt"
	"sort"
	"sync"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
)

var (
	mu  sync.RWMutex
	reg = map[string]core.RuntimeAdapter{}
)

// Register adds an adapter and its generators; duplicates panic at init time.
func Register(a core.RuntimeAdapter) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := reg[a.Name()]; ok {
		panic(fmt.Sprintf("runtimes: %q registered twice", a.Name()))
	}
	reg[a.Name()] = a
	for _, g := range a.Generators() {
		rrsync.Register(g)
	}
}

func Lookup(name string) (core.RuntimeAdapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := reg[name]
	return a, ok
}

// Names returns registered runtime names, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(reg))
	for n := range reg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
