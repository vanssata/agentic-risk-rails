package github

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// PolicyCheck is the required status check context: the job name of the
// generated rr-policy-check workflow.
const PolicyCheck = "rr-policy-check"

// ActionsAppID is the GitHub Actions app; pinning it stops another app or a
// plain status from satisfying the check. [V] https://api.github.com/apps/github-actions
const ActionsAppID = 15368

// Owners returns the owners of path in a CODEOWNERS file, last matching line
// wins. Supported patterns: leading "/", "*", "**", a trailing "/" for a
// directory. Any line GitHub would skip or interpret differently (negation
// "!", ranges "[ ]", escapes) is an error: what cannot be evaluated is red.
func Owners(codeowners []byte, path string) ([]string, error) {
	var owners []string
	sc := bufio.NewScanner(bytes.NewReader(codeowners))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		ok, err := matches(f[0], path)
		if err != nil {
			return nil, err
		}
		if ok {
			owners = f[1:] // a pattern with no owner clears ownership
		}
	}
	return owners, nil
}

func matches(pat, path string) (bool, error) {
	if strings.HasPrefix(pat, "!") || strings.ContainsAny(pat, "[]\\") {
		return false, fmt.Errorf("github: unsupported CODEOWNERS pattern %q", pat)
	}
	dir := strings.HasSuffix(pat, "/")
	pat = strings.TrimSuffix(pat, "/")
	if !strings.HasPrefix(pat, "/") && !strings.Contains(pat, "/") {
		pat = "**/" + pat // gitignore: a slash-free pattern matches at any depth
	}
	pat = strings.TrimPrefix(pat, "/")
	if !dir {
		if ok, err := doublestar.Match(pat, path); err != nil || ok {
			return ok, err
		}
	}
	if dir || !strings.Contains(pat, "*") { // a directory owns its contents
		return doublestar.Match(pat+"/**", path)
	}
	return false, nil
}

// BotOwners lists owners in CODEOWNERS that are bot identities. The runner's
// App must never be a code owner (DES §3.4 step 4).
func BotOwners(codeowners []byte) []string {
	var bots []string
	sc := bufio.NewScanner(bytes.NewReader(codeowners))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		for _, o := range f[min(1, len(f)):] {
			if strings.HasSuffix(o, "[bot]") || strings.HasPrefix(o, "@apps/") {
				bots = append(bots, o)
			}
		}
	}
	return bots
}

// HumanApproved reports whether pr has a valid approval for a LOOSEN policy
// change: the reviewer's latest decision is APPROVED, on the current head
// commit, by a non-bot who is not the PR author and is a code owner (user or
// team member). Labels are never consulted. Any API error is returned.
func HumanApproved(ctx context.Context, h core.Hosting, pr core.PullRequest, owners []string) (bool, error) {
	if pr.HeadSHA == "" || len(owners) == 0 {
		return false, nil
	}
	rs, err := h.Reviews(ctx, pr.Number)
	if err != nil {
		return false, err
	}
	latest := map[string]core.Review{}
	for _, r := range rs {
		switch r.State {
		case "APPROVED", "CHANGES_REQUESTED", "DISMISSED":
			latest[strings.ToLower(r.Login)] = r
		}
	}
	for _, r := range latest {
		if r.State != "APPROVED" || r.IsBot || r.CommitID != pr.HeadSHA || r.Login == "" || strings.EqualFold(r.Login, pr.Author) {
			continue
		}
		for _, o := range owners {
			o = strings.TrimPrefix(o, "@")
			if strings.Contains(o, "/") {
				ok, err := h.IsTeamMember(ctx, o, r.Login)
				if err != nil {
					return false, err
				}
				if ok {
					return true, nil
				}
			} else if strings.EqualFold(o, r.Login) {
				return true, nil
			}
		}
	}
	return false, nil
}

// MissingRules lists the required rules absent from the live branch rules
// (GET rules/branches/{branch}). check is the required status check context.
func MissingRules(raw json.RawMessage, check string) ([]string, error) {
	var rules []struct {
		Type       string `json:"type"`
		Parameters struct {
			CodeOwners   bool `json:"require_code_owner_review"`
			Stale        bool `json:"dismiss_stale_reviews_on_push"`
			LastPush     bool `json:"require_last_push_approval"`
			Approvals    int  `json:"required_approving_review_count"`
			StatusChecks []struct {
				Context       string `json:"context"`
				IntegrationID int    `json:"integration_id"`
			} `json:"required_status_checks"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("github: rules: %w", err)
	}
	var pr, codeOwners, stale, last, count, status bool
	for _, r := range rules {
		p := r.Parameters
		switch r.Type {
		case "pull_request":
			pr = true
			codeOwners, stale, last = codeOwners || p.CodeOwners, stale || p.Stale, last || p.LastPush
			count = count || p.Approvals >= 1
		case "required_status_checks":
			for _, s := range p.StatusChecks {
				status = status || (s.Context == check && s.IntegrationID == ActionsAppID)
			}
		}
	}
	var missing []string
	for _, c := range []struct {
		ok   bool
		name string
	}{
		{pr, "pull_request"},
		{codeOwners, "require_code_owner_review"},
		{stale, "dismiss_stale_reviews_on_push"},
		{last, "require_last_push_approval"},
		{count, "required_approving_review_count>=1"},
		{status, "required_status_check " + check + " from integration " + strconv.Itoa(ActionsAppID)},
	} {
		if !c.ok {
			missing = append(missing, c.name)
		}
	}
	return missing, nil
}
