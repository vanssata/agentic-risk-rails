package main

// GitHub-backed checks used by `rr policy check --pr` and `rr sync --check --remote`
// (DES §3.4 steps 3-4). Every API error is red (fail-closed).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/gitx"
	hostgh "github.com/vanssata/agentic-risk-rails/internal/hosting/github"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

// prHosting is core.Hosting plus the GitHub-only ruleset bypass read.
type prHosting interface {
	core.Hosting
	BypassActors(ctx context.Context, rules json.RawMessage) ([]string, error)
}

// inActions: the environment is trusted only inside a GitHub Actions run. An
// agent could otherwise point GITHUB_API_URL / GITHUB_REPOSITORY at a fake
// server to get a green check (and receive the token).
func inActions() bool { return os.Getenv("GITHUB_ACTIONS") == "true" }

// newHosting is replaced in tests (they inject a client, not env).
var newHosting = func(remote string) (prHosting, error) {
	base := ""
	if inActions() {
		base = os.Getenv("GITHUB_API_URL")
	}
	tok, err := hostgh.TokenFor(context.Background(), remote, base)
	if err != nil {
		return nil, err
	}
	return hostgh.New(remote, tok, base)
}

const codeownersFile = ".github/CODEOWNERS"

// remoteRepo is "owner/repo" from the ceiling (enterprise wins over user); a
// GitHub Actions run has no ceiling and falls back to GITHUB_REPOSITORY.
func remoteRepo() (string, error) {
	ent, user, err := policy.LoadCeilings()
	if err != nil {
		return "", err
	}
	for _, l := range []*core.Layer{ent, user} {
		if l != nil && l.Policy.Remote != "" {
			return l.Policy.Remote, nil
		}
	}
	if r := os.Getenv("GITHUB_REPOSITORY"); r != "" && inActions() {
		return r, nil
	}
	return "", errors.New("no remote: set `remote: owner/repo` in ceiling.yaml (GITHUB_REPOSITORY counts only in GitHub Actions)")
}

var prRef = regexp.MustCompile(`^refs/pull/(\d+)/`)

// prNumber is --pr, else the PR of the current GitHub Actions run; 0 = none.
func prNumber(flag int) int {
	if flag > 0 {
		return flag
	}
	if m := prRef.FindStringSubmatch(os.Getenv("GITHUB_REF")); m != nil && inActions() {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// branchOf accepts a plain branch name, origin/<b>, refs/remotes/origin/<b> or
// refs/heads/<b>. Anything else (another remote, a SHA) is ambiguous: error.
func branchOf(ref string) (string, error) {
	for _, p := range []string{"refs/remotes/origin/", "refs/heads/", "origin/"} {
		if b, ok := strings.CutPrefix(ref, p); ok && b != "" {
			return b, nil
		}
	}
	if ref == "" || strings.Contains(ref, "/") {
		return "", fmt.Errorf("--base %q: use a branch name or origin/<branch>", ref)
	}
	return ref, nil
}

// localHeads are the commits the checkout can legitimately be: HEAD and, only
// in a GitHub Actions pull_request run (merge ref), its second parent (the PR
// head). Locally an agent could build a merge commit with an approved head.
func localHeads(ctx context.Context, root string) ([]string, error) {
	revs := []string{"HEAD"}
	if inActions() && os.Getenv("GITHUB_EVENT_NAME") == "pull_request" {
		revs = append(revs, "HEAD^2")
	}
	var out []string
	for _, rev := range revs {
		b, err := gitx.Run(ctx, "", "-C", root, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
		if err != nil {
			if rev == "HEAD" {
				return nil, err
			}
			continue
		}
		out = append(out, strings.TrimSpace(string(b)))
	}
	return out, nil
}

// loosenApproved: a LOOSEN is green only with an approving review from a human
// code owner other than the author, on the PR head (hostgh.HumanApproved).
// The PR must target the base branch and be the change under test (checkout
// commit == PR head). Owners come from CODEOWNERS on the base branch.
func loosenApproved(ctx context.Context, h prHosting, base string, n int, heads []string, out io.Writer) (bool, error) {
	if n == 0 {
		fmt.Fprintln(out, "no PR given: a loosening needs an approving code-owner review (--pr N)")
		return false, nil
	}
	branch, err := branchOf(base)
	if err != nil {
		return false, err
	}
	pr, err := h.PullRequest(ctx, n)
	if err != nil {
		return false, err
	}
	if pr.Base != branch {
		fmt.Fprintf(out, "PR #%d targets %q, not %q\n", n, pr.Base, branch)
		return false, nil
	}
	if !slices.Contains(heads, pr.HeadSHA) {
		fmt.Fprintf(out, "PR #%d head %s is not the checked-out commit\n", n, pr.HeadSHA)
		return false, nil
	}
	co, err := h.ReadFile(ctx, branch, codeownersFile)
	if err != nil {
		return false, err
	}
	owners, err := hostgh.Owners(co, "riskrails.yaml")
	if err != nil {
		return false, err
	}
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
	owners, err := hostgh.Owners(co, "riskrails.yaml")
	if err != nil {
		return fmt.Errorf("L>=2 refused: %w", err)
	}
	if len(owners) == 0 {
		missing = append(missing, "CODEOWNERS entry for riskrails.yaml")
	}
	bypass, err := h.BypassActors(ctx, raw)
	if err != nil {
		return fmt.Errorf("L>=2 refused: bypass cannot be verified: %w", err)
	}
	if len(bypass) > 0 {
		missing = append(missing, "empty bypass_actors ("+strings.Join(bypass, "; ")+")")
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
