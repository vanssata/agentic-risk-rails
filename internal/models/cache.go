// Package models resolves which model candidates are usable per runtime
// (DES §4): probe, cache, tiers, ladder.
package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Cache stores probe results per runtime and account (DES §4.3.4).
type Cache struct{ Path string }

type entry struct {
	Runtime     string          `json:"runtime"`
	AccountHash string          `json:"account_hash"`
	Model       string          `json:"model"`
	State       core.ModelState `json:"state"`
	Error       string          `json:"error,omitempty"`
	ProbedAt    time.Time       `json:"probed_at"`
}

// Account keys: CLI results and install-profile results never overwrite each other.
const (
	LocalAccount   = "local"
	ProfileAccount = "local-profile"
)

// CachePath expands a leading ~/ and accepts only a path under
// <home>/.cache/riskrails/ without ".." segments: the repo policy must not
// choose where rr writes.
func CachePath(p, home string) (string, error) {
	if slices.Contains(strings.Split(filepath.ToSlash(p), "/"), "..") {
		return "", fmt.Errorf("models.probe.cache %q: .. is not allowed", p)
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		p = filepath.Join(home, rest)
	}
	p = filepath.Clean(p)
	if !strings.HasPrefix(p, filepath.Join(home, ".cache", "riskrails")+string(filepath.Separator)) {
		return "", fmt.Errorf("models.probe.cache %q must be under %s", p, filepath.Join(home, ".cache", "riskrails"))
	}
	return p, nil
}

func (c Cache) load() ([]entry, error) {
	b, err := os.ReadFile(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("models cache %s: %w", c.Path, err)
	}
	return es, nil
}

// Get returns the stored result for one model; false when absent or unreadable
// (an unreadable cache is an empty cache: nothing is PASS).
func (c Cache) Get(runtime, account, model string) (core.ProbeResult, bool) {
	es, _ := c.load()
	for _, e := range es {
		if e.Runtime == runtime && e.AccountHash == account && e.Model == model {
			return core.ProbeResult{Model: model, State: e.State, Error: e.Error, ProbedAt: e.ProbedAt}, true
		}
	}
	return core.ProbeResult{}, false
}

// Put upserts results atomically. A corrupt cache is replaced.
func (c Cache) Put(runtime, account string, rs ...core.ProbeResult) error {
	es, _ := c.load()
	for _, r := range rs {
		ne := entry{runtime, account, r.Model, r.State, r.Error, r.ProbedAt}
		found := false
		for i, e := range es {
			if e.Runtime == runtime && e.AccountHash == account && e.Model == r.Model {
				es[i], found = ne, true
			}
		}
		if !found {
			es = append(es, ne)
		}
	}
	b, err := json.MarshalIndent(es, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.Path), ".models-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.Path)
}
