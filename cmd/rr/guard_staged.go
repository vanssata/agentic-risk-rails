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
	call, err := stagedCall(ctx, projectRoot(cwd))
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

func stagedCall(ctx context.Context, root string) (core.ToolCall, error) {
	call := core.ToolCall{Runtime: "git-pre-commit", Event: "pre-commit", Tool: "Edit", Cwd: root}
	b, err := gitx.Run(ctx, "", "-C", root, "rev-parse", "--show-toplevel")
	if err != nil {
		return call, err
	}
	top := strings.TrimSpace(string(b))
	out, err := gitx.Run(ctx, "", "-C", top, "diff", "--cached", "--name-status", "--no-renames", "-z")
	if err != nil {
		return call, err
	}
	if len(out) == 0 {
		return call, nil
	}
	f := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(f)%2 != 0 {
		return call, errors.New("unexpected git diff output")
	}
	for i := 0; i < len(f); i += 2 {
		abs := filepath.Join(top, f[i+1])
		e := core.FileEdit{Path: abs, Delete: f[i] == "D"}
		if !e.Delete {
			c, err := gitx.Run(ctx, "", "-C", top, "show", ":"+f[i+1])
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
