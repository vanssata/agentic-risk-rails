package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/gitx"
)

// stagedTimeout is longer than guardTimeout: a commit may stage many files and
// a pre-commit hook has no fail-open deadline to beat.
const stagedTimeout = 60 * time.Second

// guardStaged judges what the next commit would contain (index only) as one
// multi-file Edit, with the same GuardContext as the hook path. Any error,
// deny or ask is a non-zero exit. Advice only: `git commit --no-verify` skips it.
func guardStaged(cmd *cobra.Command) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), stagedTimeout)
	defer cancel()
	errw := cmd.ErrOrStderr()
	fail := func(reason string) error {
		fmt.Fprintln(errw, "rr guard --staged: deny:", reason)
		return ExitError{Code: 2}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fail(err.Error())
	}
	// git runs the hook in the worktree top with GIT_INDEX_FILE set to a
	// temporary index for `commit -a` / `commit -- <path>`; read that one.
	idx := os.Getenv("GIT_INDEX_FILE")
	if idx != "" && !filepath.IsAbs(idx) {
		idx = filepath.Join(cwd, idx)
	}
	call, err := stagedCall(ctx, projectRoot(cwd), cwd, idx)
	if err != nil {
		return fail("cannot read the index: " + err.Error())
	}
	if len(call.Edits) == 0 {
		return nil
	}
	v := check(ctx, call, call.Runtime)
	if v.Decision == core.Allow {
		return nil
	}
	return fail(fmt.Sprintf("%s: %s [rule: %s]", v.Decision, v.Reason, v.Rule))
}

// stagedCall reads the index of the repository at cwd (where git runs the
// hook); root is only where the policy lives.
func stagedCall(ctx context.Context, root, cwd, indexFile string) (core.ToolCall, error) {
	call := core.ToolCall{Runtime: "git-pre-commit", Event: "pre-commit", Tool: "Edit", Cwd: root}
	g := func(args ...string) ([]byte, error) {
		if indexFile != "" {
			return gitx.RunIndex(ctx, indexFile, "", args...)
		}
		return gitx.Run(ctx, "", args...)
	}
	b, err := g("-C", cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		return call, err
	}
	top := strings.TrimSpace(string(b))
	out, err := g("-C", top, "diff", "--cached", "--raw", "--no-renames", "-z")
	if err != nil {
		return call, err
	}
	if len(out) == 0 {
		return call, nil
	}
	// each entry: ":<old mode> <new mode> <old sha> <new sha> <status>\0<path>\0"
	f := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(f)%2 != 0 {
		return call, errors.New("unexpected git diff output")
	}
	for i := 0; i < len(f); i += 2 {
		meta := strings.Fields(f[i])
		if len(meta) != 5 {
			return call, errors.New("unexpected git diff output")
		}
		abs := filepath.Join(top, f[i+1])
		e := core.FileEdit{Path: abs, Delete: meta[4] == "D"}
		// A gitlink (submodule) has no blob: judge only its path. A symlink's
		// staged blob is its target text, which `git show` returns.
		if !e.Delete && meta[1] != "160000" {
			c, err := g("-C", top, "show", ":"+f[i+1])
			if err != nil {
				return call, err
			}
			e.Content = string(c)
		}
		call.Edits = append(call.Edits, e)
		call.Paths = append(call.Paths, abs)
	}
	return call, nil
}
