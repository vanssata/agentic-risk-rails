package main

// GitHub-backed checks used by `rr policy check --pr` and `rr sync --check --remote`
// (DES §3.4 steps 3-4). Every API error is red (fail-closed).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	hostgh "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

// prHosting is core.Hosting plus the PR read the policy check needs.
type prHosting interface {
	core.Hosting
	PullRequest(ctx context.Context, n int) (core.PullRequest, error)
}

// newHosting is replaced in tests.
var newHosting = func(remote string) (prHosting, error) {
	return hostgh.New(remote, hostgh.TokenFromEnv(), os.Getenv("GITHUB_API_URL"))
}

const codeownersFile = ".github/CODEOWNERS"

// remoteRepo is "owner/repo" from the ceiling (user, then enterprise); CI has no
// ceiling and falls back to GITHUB_REPOSITORY.
func remoteRepo() (string, error) {
	ent, user, err := policy.LoadCeilings()
	if err != nil {
		return "", err
	}
	for _, l := range []*core.Layer{user, ent} {
		if l != nil && l.Policy.Remote != "" {
			return l.Policy.Remote, nil
		}
	}
	if r := os.Getenv("GITHUB_REPOSITORY"); r != "" {
		return r, nil
	}
	return "", errors.New("no remote: set `remote: owner/repo` in ceiling.yaml or GITHUB_REPOSITORY")
}

var prRef = regexp.MustCompile(`^refs/pull/(\d+)/`)

// prNumber is --pr, else the PR of the current GitHub Actions run; 0 = none.
func prNumber(flag int) int {
	if flag > 0 {
		return flag
	}
	if m := prRef.FindStringSubmatch(os.Getenv("GITHUB_REF")); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// branchOf strips a remote prefix: origin/main, refs/remotes/origin/main -> main.
func branchOf(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/remotes/")
	ref = strings.TrimPrefix(ref, "refs/heads/")
	return strings.TrimPrefix(ref, "origin/")
}

// loosenApproved: a LOOSEN is green only with an approving review from a human
// code owner other than the author, on the PR head (hostgh.HumanApproved).
// Owners are read from CODEOWNERS on the base branch, not from the checkout.
func loosenApproved(ctx context.Context, h prHosting, base string, n int, out io.Writer) (bool, error) {
	if n == 0 {
		fmt.Fprintln(out, "no PR given: a loosening needs an approving code-owner review (--pr N)")
		return false, nil
	}
	pr, err := h.PullRequest(ctx, n)
	if err != nil {
		return false, err
	}
	co, err := h.ReadFile(ctx, branchOf(base), codeownersFile)
	if err != nil {
		return false, err
	}
	owners := hostgh.Owners(co, "riskrails.yaml")
	ok, err := hostgh.HumanApproved(ctx, h, pr, owners)
	if err == nil && !ok {
		fmt.Fprintf(out, "PR #%d: no approving review from a human code owner (%s) other than the author on %s\n", n, strings.Join(owners, " "), pr.HeadSHA)
	}
	return ok, err
}

// remoteCheck refuses L>=2 when the live default-branch rules are incomplete or
// a bot identity is a code owner.
func remoteCheck(ctx context.Context, branch string, out io.Writer) error {
	repo, err := remoteRepo()
	if err != nil {
		return err
	}
	h, err := newHosting(repo)
	if err != nil {
		return err
	}
	raw, err := h.Rulesets(ctx, branch)
	if err != nil {
		return fmt.Errorf("L>=2 refused: %w", err)
	}
	missing, err := hostgh.MissingRules(raw, hostgh.PolicyCheck)
	if err != nil {
		return fmt.Errorf("L>=2 refused: %w", err)
	}
	co, err := h.ReadFile(ctx, branch, codeownersFile)
	if err != nil {
		return fmt.Errorf("L>=2 refused: %w", err)
	}
	bots := hostgh.BotOwners(co)
	if len(hostgh.Owners(co, "riskrails.yaml")) == 0 {
		missing = append(missing, "CODEOWNERS entry for riskrails.yaml")
	}
	if len(missing) == 0 && len(bots) == 0 {
		fmt.Fprintf(out, "remote ok: %s@%s\n", repo, branch)
		return nil
	}
	if len(missing) > 0 {
		fmt.Fprintf(out, "L>=2 refused: missing on %s@%s: %s\n", repo, branch, strings.Join(missing, ", "))
	}
	if len(bots) > 0 {
		fmt.Fprintf(out, "L>=2 refused: bot identity in CODEOWNERS: %s\n", strings.Join(bots, ", "))
	}
	return ExitError{Code: 1}
}
