package factory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
)

// runStep is the worker state machine:
// implement -> (NEEDS_CONTEXT: scout, retry once) -> scope check -> review loop -> commit.
func (f *Factory) runStep(ctx context.Context, wi int, st plan.Step) (res Result, err error) {
	res = Result{Step: st.ID}
	block := func(format string, a ...any) (Result, error) {
		res.Blocked = fmt.Sprintf(format, a...)
		return res, nil
	}
	branch := "rr/" + f.Task + "/" + st.ID
	w, err := addWorktree(ctx, f.Root, filepath.Join(f.WorkDir, st.ID), branch)
	if err != nil {
		return res, err
	}
	defer removeWorktree(context.WithoutCancel(ctx), f.Root, w, branch)
	if err := f.emit(ctx, "step_started", map[string]any{"step": st.ID, "wave": wi, "files": st.Files}); err != nil {
		return res, err
	}

	brief := briefOf(st)
	rep, err := f.work(ctx, st, "implementer", w.dir, brief)
	if err != nil {
		return res, err
	}
	if rep.Status == core.StatusNeedsContext {
		scout, err := f.work(ctx, st, "code-scout", w.dir, "Find the context this step is missing:\n"+rep.Body)
		if err != nil {
			return res, err
		}
		if rep, err = f.work(ctx, st, "implementer", w.dir, brief+"\n\nCONTEXT:\n"+scout.Body); err != nil {
			return res, err
		}
	}
	res.Status = rep.Status
	switch rep.Status {
	case core.StatusDone:
	case core.StatusDoneWithConcerns:
		res.Concerns = rep.Body
	default: // BLOCKED, a second NEEDS_CONTEXT, or an unknown status: fail closed
		return block("worker %s: %s", rep.Status, firstLine(rep.Body))
	}

	if why, err := f.checkScope(ctx, w, st); err != nil || why != "" {
		res.Blocked = why
		return res, err
	}
	ok, rounds, blocked, err := f.review(ctx, st, w, brief)
	res.Rounds = rounds
	if err != nil {
		return res, err
	}
	if blocked != "" {
		return block("%s", blocked)
	}
	if !ok {
		res.Human = true
		if err := f.emit(ctx, "review_budget", map[string]any{"step": st.ID}); err != nil {
			return res, err
		}
		return block("REVIEW_BUDGET: %d review rounds failed, a human decides", MaxReviewRounds)
	}

	sha, err := commit(ctx, w, "step "+st.ID)
	if err != nil {
		return res, err
	}
	if err := f.emit(ctx, "step_committed", map[string]any{"step": st.ID, "sha": sha}); err != nil {
		return res, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := git(ctx, f.Root, "cherry-pick", sha); err != nil {
		_, _ = git(ctx, f.Root, "cherry-pick", "--abort")
		return res, err
	}
	head, err := git(ctx, f.Root, "rev-parse", "HEAD")
	if err != nil {
		return res, err
	}
	res.Commit = strings.TrimSpace(head)
	return res, f.emit(ctx, "step_integrated", map[string]any{"step": st.ID, "sha": res.Commit})
}

// checkScope returns why the worktree may not be reviewed or committed ("" if
// fine): a filter or merge attribute, a change outside the step's files, or a symlink
// in a changed path. A violation is journalled.
func (f *Factory) checkScope(ctx context.Context, w worktree, st plan.Step) (string, error) {
	why, err := scopeViolation(ctx, w, st)
	if err != nil || why == "" {
		return "", err
	}
	why = "scope: " + why
	return why, f.emit(ctx, "scope_violation", map[string]any{"step": st.ID, "reason": why})
}

// verify is the last gate before commit: the worktree must still be in scope
// and stage to exactly the tree the reviewers saw. "" means commit the index.
func (f *Factory) verify(ctx context.Context, w worktree, st plan.Step, reviewed string) (string, error) {
	if why, err := f.checkScope(ctx, w, st); err != nil || why != "" {
		return why, err
	}
	tree, err := stage(ctx, w, st.Files)
	why := ""
	switch {
	case errors.Is(err, errNotRegular):
		why = "scope: " + err.Error()
	case err != nil:
		return "", err
	case tree != reviewed:
		why = "scope: worktree changed after review"
	default:
		return "", nil
	}
	return why, f.emit(ctx, "scope_violation", map[string]any{"step": st.ID, "reason": why})
}

func scopeViolation(ctx context.Context, w worktree, st plan.Step) (string, error) {
	bad, err := attrPaths(ctx, w)
	if err != nil {
		return "", err
	}
	if len(bad) > 0 {
		return "filter or merge attribute on " + strings.Join(bad, ", "), nil
	}
	changed, ignored, err := statusFiles(ctx, w)
	if err != nil {
		return "", err
	}
	for _, p := range ignored {
		if steersClaude(p) {
			return "ignored file that configures the agent: " + p, nil
		}
	}
	for _, c := range changed {
		if why := badPath(w.dir, c); why != "" {
			return why, nil
		}
	}
	if out := outside(changed, st.Files); len(out) > 0 {
		return "worker changed files outside the step: " + strings.Join(out, ", "), nil
	}
	return "", nil
}

// steersClaude: ignored paths a `claude -p` would read as configuration.
func steersClaude(p string) bool {
	p = strings.TrimSuffix(filepath.ToSlash(p), "/")
	if p == ".claude" || strings.HasPrefix(p, ".claude/") || strings.Contains(p, "/.claude/") {
		return true
	}
	switch path.Base(p) {
	case ".mcp.json", "CLAUDE.md", "AGENTS.md":
		return true
	}
	return false
}

// badPath rejects a changed path that is, or lies below, a symlink, or that is
// a directory (a nested repository would be committed as a gitlink).
func badPath(dir, rel string) string {
	rel = strings.TrimSuffix(filepath.ToSlash(rel), "/")
	cur := dir
	for _, part := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			return "" // deleted or never existed
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "symlink in changed path " + rel
		}
		if fi.IsDir() && cur == filepath.Join(dir, filepath.FromSlash(rel)) {
			return "changed path is a directory (nested repository?): " + rel
		}
	}
	return ""
}
