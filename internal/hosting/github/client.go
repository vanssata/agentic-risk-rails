// Package github implements core.Hosting over the GitHub REST API (DES §3.4
// steps 3-4, §8.2). Facts: docs/research/verified/github.md.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	gh "github.com/google/go-github/v93/github"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Client is a core.Hosting bound to one repository. owner/repo come from the
// ceiling ("remote"), never from .git/config.
type Client struct {
	gh          *gh.Client
	owner, repo string
}

var _ core.Hosting = (*Client)(nil)

// TokenFromEnv returns RR_GITHUB_TOKEN, else GITHUB_TOKEN. It is never logged.
func TokenFromEnv() string {
	if t := os.Getenv("RR_GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}

// New binds a client to "owner/repo". baseURL "" means api.github.com; any
// other base must be https, or the token could be sent in clear text.
func New(remote, token, baseURL string) (*Client, error) {
	if baseURL != "" && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("github: API base URL must be https")
	}
	return newAt(remote, token, baseURL)
}

// newAt is New without the scheme check; tests point it at httptest servers.
func newAt(remote, token, baseURL string) (*Client, error) {
	owner, repo, ok := strings.Cut(remote, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return nil, fmt.Errorf("github: remote %q is not owner/repo", remote)
	}
	opts := []gh.ClientOptionsFunc{gh.WithTimeout(30 * time.Second)}
	if token != "" {
		opts = append(opts, gh.WithAuthToken(token))
	}
	if baseURL != "" {
		u := strings.TrimSuffix(baseURL, "/") + "/"
		opts = append(opts, gh.WithURLs(&u, &u))
	}
	c, err := gh.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	return &Client{gh: c, owner: owner, repo: repo}, nil
}

func isStatus(resp *gh.Response, code int) bool {
	return resp != nil && resp.Response != nil && resp.StatusCode == code
}

// ReadFile reads path at ref. Only a 404 maps to core.ErrNotFound.
func (c *Client) ReadFile(ctx context.Context, ref, path string) ([]byte, error) {
	f, _, resp, err := c.gh.Repositories.GetContents(ctx, c.owner, c.repo, path, &gh.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		if isStatus(resp, http.StatusNotFound) {
			return nil, fmt.Errorf("%s:%s: %w", ref, path, core.ErrNotFound)
		}
		return nil, fmt.Errorf("github: read %s:%s: %w", ref, path, err)
	}
	if f == nil {
		return nil, fmt.Errorf("github: %s:%s is not a file", ref, path)
	}
	s, err := f.GetContent()
	if err != nil {
		return nil, fmt.Errorf("github: decode %s:%s: %w", ref, path, err)
	}
	return []byte(s), nil
}

// OpenDraftPR opens a draft pull request from head into base.
func (c *Client) OpenDraftPR(ctx context.Context, head, base, title, body string) (core.PullRequest, error) {
	draft := true
	pr, _, err := c.gh.PullRequests.Create(ctx, c.owner, c.repo, gh.CreatePullRequest{
		Title: &title, Head: head, Base: base, Body: &body, Draft: &draft,
	})
	if err != nil {
		return core.PullRequest{}, fmt.Errorf("github: open draft PR: %w", err)
	}
	return toPR(pr), nil
}

// PullRequest reads one PR (author, head SHA and base branch for the policy check).
func (c *Client) PullRequest(ctx context.Context, n int) (core.PullRequest, error) {
	pr, _, err := c.gh.PullRequests.Get(ctx, c.owner, c.repo, n)
	if err != nil {
		return core.PullRequest{}, fmt.Errorf("github: PR %d: %w", n, err)
	}
	return toPR(pr), nil
}

func toPR(pr *gh.PullRequest) core.PullRequest {
	return core.PullRequest{
		Number: pr.GetNumber(), Author: pr.GetUser().GetLogin(),
		URL: pr.GetHTMLURL(), HeadSHA: pr.GetHead().GetSHA(), Base: pr.GetBase().GetRef(),
	}
}

// Reviews returns every review of the PR (all pages), oldest first.
func (c *Client) Reviews(ctx context.Context, pr int) ([]core.Review, error) {
	var out []core.Review
	opt := &gh.ListOptions{PerPage: 100}
	for {
		rs, resp, err := c.gh.PullRequests.ListReviews(ctx, c.owner, c.repo, pr, opt)
		if err != nil {
			return nil, fmt.Errorf("github: reviews of PR %d: %w", pr, err)
		}
		for _, r := range rs {
			u := r.GetUser()
			// A null user or a Bot is never a human approver.
			bot := u == nil || u.GetType() == "Bot" || strings.HasSuffix(u.GetLogin(), "[bot]")
			out = append(out, core.Review{Login: u.GetLogin(), State: r.GetState(), IsBot: bot, CommitID: r.GetCommitID()})
		}
		if resp.NextPage == 0 {
			return out, nil
		}
		opt.Page = resp.NextPage
	}
}

// IsTeamMember: team is "org/slug", or "slug" in the repository owner's org.
// 404 means not a member; a pending invitation does not count.
func (c *Client) IsTeamMember(ctx context.Context, team, login string) (bool, error) {
	org, slug, ok := strings.Cut(strings.TrimPrefix(team, "@"), "/")
	if !ok {
		org, slug = c.owner, org
	}
	m, resp, err := c.gh.Teams.GetTeamMembershipBySlug(ctx, org, slug, login)
	if err != nil {
		switch {
		case isStatus(resp, http.StatusNotFound):
			return false, nil
		case isStatus(resp, http.StatusForbidden):
			return false, fmt.Errorf("github: membership %s/%s: token lacks org members:read (use RR_GITHUB_TOKEN): %w", org, slug, err)
		}
		return false, fmt.Errorf("github: membership %s/%s %s: %w", org, slug, login, err)
	}
	return m.GetState() == "active", nil
}

// Rulesets returns the active rules that apply to branch (JSON array).
func (c *Client) Rulesets(ctx context.Context, branch string) (json.RawMessage, error) {
	all := []json.RawMessage{}
	for page := 1; page > 0; {
		req, err := c.gh.NewRequest(ctx, http.MethodGet, fmt.Sprintf("repos/%s/%s/rules/branches/%s?per_page=100&page=%d", c.owner, c.repo, url.PathEscape(branch), page), nil)
		if err != nil {
			return nil, fmt.Errorf("github: %w", err)
		}
		var rules []json.RawMessage
		resp, err := c.gh.Do(req, &rules)
		if err != nil {
			return nil, fmt.Errorf("github: rules for %s: %w", branch, err)
		}
		all = append(all, rules...)
		page = resp.NextPage
	}
	raw, err := json.Marshal(all)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	return raw, nil
}

// BypassActors lists the bypass actors of every ruleset behind rules (the
// output of Rulesets). A ruleset that cannot be read, or whose bypass_actors
// are not returned (needs write access to the ruleset), is an error: bypass
// that cannot be verified counts as present.
func (c *Client) BypassActors(ctx context.Context, rules json.RawMessage) ([]string, error) {
	var rs []struct {
		ID     int    `json:"ruleset_id"`
		Type   string `json:"ruleset_source_type"`
		Source string `json:"ruleset_source"`
	}
	if err := json.Unmarshal(rules, &rs); err != nil {
		return nil, fmt.Errorf("github: rules: %w", err)
	}
	var out []string
	seen := map[string]bool{}
	for _, r := range rs {
		if r.ID == 0 {
			return nil, errors.New("github: rule without ruleset_id, bypass cannot be verified")
		}
		path := fmt.Sprintf("repos/%s/%s/rulesets/%d", c.owner, c.repo, r.ID)
		if r.Type == "Organization" {
			path = fmt.Sprintf("orgs/%s/rulesets/%d", r.Source, r.ID)
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		req, err := c.gh.NewRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, fmt.Errorf("github: %w", err)
		}
		var rs struct {
			Bypass *[]struct {
				ActorType string `json:"actor_type"`
				ActorID   int    `json:"actor_id"`
			} `json:"bypass_actors"`
		}
		if _, err := c.gh.Do(req, &rs); err != nil {
			return nil, fmt.Errorf("github: ruleset %d: %w", r.ID, err)
		}
		if rs.Bypass == nil {
			return nil, fmt.Errorf("github: ruleset %d: bypass_actors not returned (token needs write access to the ruleset)", r.ID)
		}
		for _, b := range *rs.Bypass {
			out = append(out, fmt.Sprintf("ruleset %d: %s %d", r.ID, b.ActorType, b.ActorID))
		}
	}
	return out, nil
}
