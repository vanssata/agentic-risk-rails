package flow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/research"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// defaultCacheDir is the DES §5.5 research cache, outside the agent's write-set.
const defaultCacheDir = "~/.cache/riskrails/research/<repo-hash>"

// Researched is the result of Research.
type Researched struct {
	Roles      []string
	CacheHits  int
	Brief      string // path of the merge brief in the task's state; empty for light
	BriefToken int
}

// BriefPath is the merge brief of a task: in the state dir, never in the checkout's write-set.
func (e Env) BriefPath(task string) string {
	return filepath.Join(journal.RunDir(e.state()), task+".research.md")
}

// cacheDir resolves the policy cache dir; one inside the checkout would be inside
// the agent's write-set, so it is refused.
func (e Env) cacheDir() (string, error) {
	tmpl := e.Policy.Policy.Research.Cache.Dir
	if tmpl == "" {
		tmpl = defaultCacheDir
	}
	if strings.HasPrefix(tmpl, "~/") && e.Home == "" {
		return "", errors.New("research cache dir needs a home directory")
	}
	dir := research.RepoDir(tmpl, e.Home, e.Root)
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("research cache dir %q must be absolute", dir)
	}
	if rel, err := filepath.Rel(e.Root, dir); err == nil && !strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("research cache dir %q is inside the checkout", dir)
	}
	return dir, nil
}

// Research runs the read-only scouts of the task's mode at the current HEAD
// (DES §5.3), merges them and writes the merge brief (at most
// research.MaxBriefTokens) into the task's state. Light has no scouts. Partial
// research is not accepted: if any scout fails the failure is journaled in
// research_scouts_done, no brief is written and Research returns an error (the
// scouts that succeeded stay in the cache, so a rerun costs only the failed ones).
func (e Env) Research(ctx context.Context, task string, runner core.WorkerRunner, runtime string) (Researched, error) {
	events, err := e.Journal.Events(ctx, task)
	if err != nil {
		return Researched{}, err
	}
	d, err := readStarted(events)
	if err != nil {
		return Researched{}, err
	}
	mode, err := verify.TaskMode(events)
	if err != nil {
		return Researched{}, err
	}
	spec := e.Policy.Policy.Research
	roles, err := research.RolesFor(spec, mode)
	if err != nil {
		return Researched{}, err
	}
	if len(roles) == 0 {
		return Researched{}, nil
	}
	dir, err := e.cacheDir()
	if err != nil {
		return Researched{}, err
	}
	sha, err := verify.HeadSHA(ctx, e.Root)
	if err != nil {
		return Researched{}, err
	}
	tr, err := verify.LoadTrust(e.state(), task, events)
	if err != nil {
		return Researched{}, err
	}
	changed, err := verify.TaskChanged(ctx, e.Root, tr, true)
	if err != nil {
		return Researched{}, err
	}
	inv := research.Inv{Root: e.Root, Changed: changed, Now: time.Now()}
	if pin := spec.TechDocs.PinFrom; pin != "" {
		if b, err := os.ReadFile(filepath.Join(e.Root, pin)); err == nil {
			h := sha256.Sum256(b)
			inv.LockHash = hex.EncodeToString(h[:])
		}
	}
	meter := e.meter(task, runtime)
	res, err := research.Run(ctx, meter.Wrap(inRoot{runner, e.Root}), dir, spec, research.Request{
		SHA: sha, Question: d.Goal, Goal: d.Goal, Known: Expand(d.Scope, e.Tree), Mode: mode, Inv: inv})
	if err != nil {
		return Researched{}, err
	}
	m := research.Merge(res.Reports)
	done := map[string]any{"mode": mode, "roles": roles, "cache_hits": res.CacheHits, "tokens": m.Tokens, "calls": m.Calls}
	if len(res.Errors) > 0 {
		var msgs []string
		for _, se := range res.Errors {
			msgs = append(msgs, se.Error())
		}
		done["errors"] = msgs
	}
	if err := e.append(ctx, task, "research_scouts_done", core.ActorAutonomy, done); err != nil {
		return Researched{}, err
	}
	if err := errors.Join(res.Errors...); err != nil {
		return Researched{}, fmt.Errorf("research incomplete, no brief written: %w", err)
	}
	brief := research.MergeBrief(m, research.MaxBriefTokens)
	out := Researched{Roles: roles, CacheHits: res.CacheHits, Brief: e.BriefPath(task), BriefToken: research.EstimateTokens(brief)}
	if err := os.MkdirAll(journal.RunDir(e.state()), 0o755); err != nil {
		return Researched{}, err
	}
	if err := os.WriteFile(out.Brief, []byte(brief), 0o600); err != nil {
		return Researched{}, err
	}
	err = e.append(ctx, task, "research_merged", core.ActorAutonomy, map[string]any{"facts": len(m.Facts),
		"conflicts": len(m.Conflicts), "gaps": len(m.Gaps), "brief_tokens": out.BriefToken})
	return out, err
}

// inRoot runs scouts in the checkout (they are read-only runners).
type inRoot struct {
	inner core.WorkerRunner
	root  string
}

func (r inRoot) Run(ctx context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	spec.Worktree = r.root
	return r.inner.Run(ctx, spec)
}
