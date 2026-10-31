package factory

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// gitHardening is a copy of internal/policy.gitHardening (errata #16): rr runs
// git outside the agent sandbox in a repo the agent may have poisoned. Replace
// with an exported policy helper once available (CORE_CHANGE_REQUESTS).
var gitHardening = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.pager=cat",
	"-c", "core.sshCommand=false",
	"-c", "core.askPass=false",
	"-c", "core.alternateRefsCommand=",
	"-c", "core.untrackedCache=false",
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

func git(ctx context.Context, dir string, args ...string) (string, error) {
	full := append(append(append([]string{}, gitHardening...), "-C", dir), args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = gitEnv()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// addWorktree creates a worktree of root at dir on a new branch.
func addWorktree(ctx context.Context, root, dir, branch string) error {
	_, err := git(ctx, root, "worktree", "add", "-q", "-b", branch, dir, "HEAD")
	return err
}

func removeWorktree(ctx context.Context, root, dir, branch string) {
	_, _ = git(ctx, root, "worktree", "remove", "--force", dir)
	_, _ = git(ctx, root, "branch", "-D", branch)
}

// changedFiles lists paths modified, added, deleted or untracked in dir.
func changedFiles(ctx context.Context, dir string) ([]string, error) {
	out, err := git(ctx, dir, "status", "--porcelain", "-z", "--untracked-files=all")
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
func stage(ctx context.Context, dir string, files []string) (string, error) {
	if _, err := git(ctx, dir, append([]string{"add", "-A", "--"}, files...)...); err != nil {
		return "", err
	}
	return git(ctx, dir, "diff", "--cached", "--no-ext-diff", "--no-textconv")
}

// commit commits the staged index of dir and returns the new SHA.
func commit(ctx context.Context, dir, msg string) (string, error) {
	if _, err := git(ctx, dir, "commit", "-q", "-m", msg); err != nil {
		return "", err
	}
	out, err := git(ctx, dir, "rev-parse", "HEAD")
	return strings.TrimSpace(out), err
}
