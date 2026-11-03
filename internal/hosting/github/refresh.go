package github

import (
	"context"
	"encoding/json"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Refreshing is a core.Hosting for long-lived callers (the unattended runner):
// every operation takes the token from TokenFor, whose cache mints a new App
// installation token before the old one expires, so a run longer than an hour
// keeps working. A token error fails the operation (fail-closed).
type Refreshing struct {
	Remote, BaseURL string
	token           func(ctx context.Context, remote, baseURL string) (string, error) // nil = TokenFor
}

var _ core.Hosting = Refreshing{}

func (r Refreshing) client(ctx context.Context) (*Client, error) {
	tf := r.token
	if tf == nil {
		tf = TokenFor
	}
	tok, err := tf(ctx, r.Remote, r.BaseURL)
	if err != nil {
		return nil, err
	}
	return New(r.Remote, tok, r.BaseURL)
}

func (r Refreshing) ReadFile(ctx context.Context, ref, path string) ([]byte, error) {
	c, err := r.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.ReadFile(ctx, ref, path)
}

func (r Refreshing) OpenDraftPR(ctx context.Context, head, base, title, body string, labels []string) (core.PullRequest, error) {
	c, err := r.client(ctx)
	if err != nil {
		return core.PullRequest{}, err
	}
	return c.OpenDraftPR(ctx, head, base, title, body, labels)
}

func (r Refreshing) Push(ctx context.Context, root, branch string) error {
	c, err := r.client(ctx)
	if err != nil {
		return err
	}
	return c.Push(ctx, root, branch)
}

func (r Refreshing) BranchSHA(ctx context.Context, branch string) (string, error) {
	c, err := r.client(ctx)
	if err != nil {
		return "", err
	}
	return c.BranchSHA(ctx, branch)
}

func (r Refreshing) PullRequest(ctx context.Context, n int) (core.PullRequest, error) {
	c, err := r.client(ctx)
	if err != nil {
		return core.PullRequest{}, err
	}
	return c.PullRequest(ctx, n)
}

func (r Refreshing) Reviews(ctx context.Context, pr int) ([]core.Review, error) {
	c, err := r.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.Reviews(ctx, pr)
}

func (r Refreshing) IsTeamMember(ctx context.Context, team, login string) (bool, error) {
	c, err := r.client(ctx)
	if err != nil {
		return false, err
	}
	return c.IsTeamMember(ctx, team, login)
}

func (r Refreshing) Rulesets(ctx context.Context, branch string) (json.RawMessage, error) {
	c, err := r.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.Rulesets(ctx, branch)
}
