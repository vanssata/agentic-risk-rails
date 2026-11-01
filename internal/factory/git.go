package factory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/gitx"
)

// commitIdentity makes rr's step commits independent of user config (which
// gitx disables) and unsigned.
var commitIdentity = []string{"-c", "commit.gpgsign=false", "-c", "user.name=rr", "-c", "user.email=rr@localhost"}

func run(ctx context.Context, dir, stdin string, args ...string) (string, error) {
	out, err := gitx.Run(ctx, stdin, append(append(append([]string{}, commitIdentity...), "-C", dir), args...)...)
	return string(out), err
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	return run(ctx, dir, "", args...)
}

// worktree is a step checkout. Its `.git` FILE is writable by the worker, so it
// is never read: every command names the git dir (taken from git right after
// creation, before the worker starts) and the work tree explicitly. That also
// stops git from walking up into a parent repo if `.git` is deleted.
type worktree struct{ dir, gitdir string }

func (w worktree) args(args []string) []string {
	return append([]string{"--git-dir=" + w.gitdir, "--work-tree=" + w.dir, "--literal-pathspecs"}, args...)
}

func (w worktree) git(ctx context.Context, args ...string) (string, error) {
	return run(ctx, w.dir, "", w.args(args)...)
}

// addWorktree creates a worktree of root at dir on a new branch.
func addWorktree(ctx context.Context, root, dir, branch string) (worktree, error) {
	if _, err := git(ctx, root, "worktree", "add", "-q", "-b", branch, dir, "HEAD"); err != nil {
		return worktree{}, err
	}
	gd, err := git(ctx, dir, "rev-parse", "--absolute-git-dir")
	return worktree{dir: dir, gitdir: strings.TrimSpace(gd)}, err
}

func removeWorktree(ctx context.Context, root string, w worktree, branch string) {
	if _, err := git(ctx, root, "worktree", "remove", "--force", w.dir); err != nil {
		_ = os.RemoveAll(w.dir)
		_, _ = git(ctx, root, "worktree", "prune")
	}
	_, _ = git(ctx, root, "branch", "-D", branch)
}

var errNotRegular = errors.New("staged entry is not a regular file")

// builtinMerge are the merge attribute values that run no configured driver.
var builtinMerge = map[string]bool{"unspecified": true, "set": true, "unset": true, "text": true, "binary": true, "union": true}

// unchanged reports whether the staged tree equals HEAD's.
func unchanged(ctx context.Context, w worktree) (bool, error) {
	head, err := w.git(ctx, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return false, err
	}
	idx, err := w.git(ctx, "write-tree")
	return head == idx, err
}

// attrPaths lists the non-ignored files of w, plus extra paths, that carry a
// `filter` attribute (clean/smudge programs come from untrusted config) or a
// custom `merge` driver. `diff` drivers are inert here: external diff and
// textconv are disabled and diff runs with --no-ext-diff --no-textconv.
func attrPaths(ctx context.Context, w worktree, extra ...string) ([]string, error) {
	list, err := w.git(ctx, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	for _, e := range extra {
		list += e + "\x00"
	}
	if list == "" {
		return nil, nil
	}
	out, err := run(ctx, w.dir, list, w.args([]string{"check-attr", "--stdin", "-z", "filter", "merge"})...)
	if err != nil {
		return nil, err
	}
	f := strings.Split(out, "\x00")
	var bad []string
	for i := 0; i+2 < len(f); i += 3 {
		path, attr, val := f[i], f[i+1], f[i+2]
		if (attr == "filter" && val != "unspecified") || (attr == "merge" && !builtinMerge[val]) {
			bad = append(bad, path)
		}
	}
	return bad, nil
}

// statusFiles lists paths modified, added, deleted or untracked in w, and
// separately the ignored ones (worker-written files git would never commit).
func statusFiles(ctx context.Context, w worktree) (changed, ignored []string, err error) {
	out, err := w.git(ctx, "status", "--porcelain", "-z", "--untracked-files=all", "--ignored")
	if err != nil {
		return nil, nil, err
	}
	parts := strings.Split(out, "\x00")
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if len(p) < 4 {
			continue
		}
		if p[:2] == "!!" {
			ignored = append(ignored, p[3:])
			continue
		}
		changed = append(changed, p[3:])
		if p[0] == 'R' || p[0] == 'C' { // the next entry is the rename source
			i++
			if i < len(parts) {
				changed = append(changed, parts[i])
			}
		}
	}
	return changed, ignored, nil
}

// stage stages exactly files (adds, edits and deletes) and returns the staged
// tree id. Only regular files (modes 100644/100755) or deletions may be staged:
// a symlink (120000) or gitlink (160000) is an error.
func stage(ctx context.Context, w worktree, files []string) (tree string, err error) {
	// a declared file that never came to exist is no pathspec error, just no change
	known, err := w.git(ctx, append([]string{"ls-files", "-z", "--cached", "--others", "--exclude-standard", "--"}, files...)...)
	if err != nil {
		return "", err
	}
	if present := strings.Split(strings.TrimRight(known, "\x00"), "\x00"); known != "" {
		if _, err := w.git(ctx, append([]string{"add", "-A", "--"}, present...)...); err != nil {
			return "", err
		}
	}
	raw, err := w.git(ctx, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv")
	if err != nil {
		return "", err
	}
	for _, tok := range strings.Split(raw, "\x00") {
		if !strings.HasPrefix(tok, ":") {
			continue
		}
		f := strings.Fields(tok)
		if len(f) < 2 || (f[1] != "100644" && f[1] != "100755" && f[1] != "000000") {
			return "", fmt.Errorf("%w: %s", errNotRegular, tok)
		}
	}
	out, err := w.git(ctx, "write-tree")
	return strings.TrimSpace(out), err
}

// diff returns the staged diff, for the reviewers.
func diff(ctx context.Context, w worktree) (string, error) {
	return w.git(ctx, "diff", "--cached", "--no-ext-diff", "--no-textconv")
}

// commit commits the staged index of w and returns the new SHA.
func commit(ctx context.Context, w worktree, msg string) (string, error) {
	if _, err := w.git(ctx, "commit", "-q", "-m", msg); err != nil {
		return "", err
	}
	out, err := w.git(ctx, "rev-parse", "HEAD")
	return strings.TrimSpace(out), err
}
