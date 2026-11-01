package main

// Orchestrator wiring after wave 1: the real policy resolver replaces the
// strict stand-ins in internal/wiring and internal/sync. Model tiers come from the
// committed .rr/tiers.lock, validated against the policy's candidates (W2-B).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	"github.com/vanssata/agentic-risk-rails/internal/wiring"
)

func init() {
	wiring.GuardContext = guardContext
	rrsync.InputProvider = syncInput
}

// resolved is the effective policy of a checkout plus what guard and sync need.
type resolved struct {
	svc   *policy.Service
	eff   core.EffectivePolicy
	files []string
	level core.Level
	root  string
	home  string
}

func resolve(ctx context.Context, root string) (resolved, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return resolved{}, err
	}
	// Files for glob-set confirmation: working tree ∪ the default branch's tree,
	// so removing a file from the index cannot hide it (wave-1 review).
	// Not a git checkout ⇒ nil file list; the differ treats unverifiable glob changes as LOOSEN.
	files, _ := policy.ListFiles(ctx, abs)
	if ref, ok := policy.DefaultRef(ctx, abs); ok {
		if base, err := policy.ListFilesAt(ctx, abs, ref); err == nil {
			files = unionSorted(files, base)
		}
	}
	svc := policy.New()
	svc.Files = func(context.Context) ([]string, error) { return files, nil }

	ent, user, err := policy.LoadCeilings()
	if err != nil {
		return resolved{}, err
	}
	inForce, err := policy.InForce(ctx, abs)
	if err != nil {
		return resolved{}, err
	}
	layers := core.PolicyLayers{Enterprise: ent, User: user, DefaultBranch: &inForce}

	wt := filepath.Join(abs, "riskrails.yaml")
	if b, err := os.ReadFile(wt); err == nil {
		p, err := policy.Load(b)
		if err != nil {
			return resolved{}, err // an unparsable working-tree policy is not silently ignored
		}
		layers.WorkingTree = &core.Layer{Policy: p, Raw: b, Source: wt}
	} else if !errors.Is(err, os.ErrNotExist) {
		return resolved{}, err
	}

	eff, err := svc.Resolve(ctx, layers)
	if err != nil {
		return resolved{}, err
	}
	// Interactive hooks and committed manifests run at most at L1 (SyncInput doc);
	// L≥2 is granted only by the runner (wave 3).
	level := core.L1
	if c := eff.Policy.Autonomy.Ceiling; c != nil && *c < level {
		level = *c
	}
	home, _ := os.UserHomeDir()
	return resolved{svc: svc, eff: eff, files: files, level: level, root: abs, home: home}, nil
}

func unionSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func guardContext(ctx context.Context, root, runtime string) (core.GuardContext, error) {
	r, err := resolve(ctx, root)
	if err != nil {
		return core.GuardContext{}, err
	}
	return core.GuardContext{
		Policy: r.eff, Level: r.level, Root: r.root, Home: r.home,
		RepoFiles: r.files, Loader: r.svc, Differ: r.svc,
		Tiers: models.ForSync(ctx, r.eff.Policy.Models, r.root)[runtime],
	}, nil
}

func syncInput(ctx context.Context, root string) (core.SyncInput, error) {
	r, err := resolve(ctx, root)
	if err != nil {
		return core.SyncInput{}, err
	}
	return core.SyncInput{Root: r.root, Home: r.home, Policy: r.eff, Level: r.level,
		Tiers: models.ForSync(ctx, r.eff.Policy.Models, r.root)}, nil
}
