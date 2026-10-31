package factory

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// gitHardening is a copy of internal/policy.gitHardening (errata #16) plus
// attribute hardening: rr runs git outside the agent sandbox in a repo the
// agent may have poisoned. Replace with a shared helper after merge.
var gitHardening = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.pager=cat",
	"-c", "core.sshCommand=false",
	"-c", "core.askPass=false",
	"-c", "core.alternateRefsCommand=",
	"-c", "core.untrackedCache=false",
	"-c", "core.attributesFile=/dev/null",
	"-c", "protocol.allow=never",
	"-c", "credential.helper=",
	"-c", "diff.external=",
	"-c", "commit.gpgsign=false",
	"-c", "user.name=rr",
	"-c", "user.email=rr@localhost",
	"--no-pager",
}

func gitEnv() []string {
	env := []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"LC_ALL=C",
	}
	for _, k := range []string{"PATH", "HOME", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func run(ctx context.Context, dir, stdin string, args ...string) (string, error) {
	full := append(append(append([]string{}, gitHardening...), "-C", dir), args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = gitEnv()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", subcommand(args), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	return run(ctx, dir, "", args...)
}

func subcommand(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return "?"
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

// filterPaths lists the non-ignored files of w that carry a `filter` attribute.
// Clean/smudge filters run program text from config, which is not trusted: a
// step touching such a file is refused before any command that could run one.
func filterPaths(ctx context.Context, w worktree) ([]string, error) {
	list, err := w.git(ctx, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil || list == "" {
		return nil, err
	}
	out, err := run(ctx, w.dir, list, w.args([]string{"check-attr", "--stdin", "-z", "filter"})...)
	if err != nil {
		return nil, err
	}
	f := strings.Split(out, "\x00")
	var bad []string
	for i := 0; i+2 < len(f); i += 3 {
		if f[i+2] != "unspecified" {
			bad = append(bad, f[i])
		}
	}
	return bad, nil
}

// changedFiles lists paths modified, added, deleted or untracked in w.
func changedFiles(ctx context.Context, w worktree) ([]string, error) {
	out, err := w.git(ctx, "status", "--porcelain", "-z", "--untracked-files=all")
	if err != nil {
		return nil, err
	}
	var files []string
	parts := strings.Split(out, "\x00")
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if len(p) < 4 {
			continue
		}
		files = append(files, p[3:])
		if p[0] == 'R' || p[0] == 'C' { // the next entry is the rename source
			i++
			if i < len(parts) {
				files = append(files, parts[i])
			}
		}
	}
	return files, nil
}

// stage stages exactly files (adds, edits and deletes) and returns the staged diff.
func stage(ctx context.Context, w worktree, files []string) (string, error) {
	if _, err := w.git(ctx, append([]string{"add", "-A", "--"}, files...)...); err != nil {
		return "", err
	}
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
