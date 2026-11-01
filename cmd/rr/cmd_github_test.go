package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

type fakePR struct {
	*fakes.Hosting
	pr         core.PullRequest
	reviewsErr error
}

func (f fakePR) PullRequest(context.Context, int) (core.PullRequest, error) { return f.pr, nil }

func (f fakePR) Reviews(ctx context.Context, n int) ([]core.Review, error) {
	if f.reviewsErr != nil {
		return nil, f.reviewsErr
	}
	return f.Hosting.Reviews(ctx, n)
}

const head = "h1"

func prHost(reviews []core.Review, reviewsErr error) fakePR {
	return fakePR{
		Hosting: &fakes.Hosting{
			Files:    map[string][]byte{"main:.github/CODEOWNERS": []byte("riskrails.yaml @acme/owners\n")},
			ReviewsM: map[int][]core.Review{7: reviews},
			Teams:    map[string][]string{"acme/owners": {"bob", "alice"}},
		},
		pr:         core.PullRequest{Number: 7, Author: "alice", HeadSHA: head},
		reviewsErr: reviewsErr,
	}
}

func TestLoosenApprovalTable(t *testing.T) {
	approve := func(login, commit string, bot bool) []core.Review {
		return []core.Review{{Login: login, State: "APPROVED", CommitID: commit, IsBot: bot}}
	}
	tests := []struct {
		name    string
		n       int
		reviews []core.Review
		revErr  error
		want    bool
		wantErr bool
	}{
		{"no PR given", 0, approve("bob", head, false), nil, false, false},
		{"no review", 7, nil, nil, false, false},
		{"label only (comment review)", 7, []core.Review{{Login: "bob", State: "COMMENTED", CommitID: head}}, nil, false, false},
		{"app approves", 7, approve("rr-app[bot]", head, true), nil, false, false},
		{"author approves", 7, approve("alice", head, false), nil, false, false},
		{"non-member approves", 7, approve("mallory", head, false), nil, false, false},
		{"stale approval", 7, approve("bob", "old", false), nil, false, false},
		{"code-owner human on head", 7, approve("bob", head, false), nil, true, false},
		{"API error", 7, nil, errors.New("500"), false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			ok, err := loosenApproved(context.Background(), prHost(tc.reviews, tc.revErr), "origin/main", tc.n, &out)
			assert.Equal(t, tc.wantErr, err != nil)
			assert.Equal(t, tc.want, ok, out.String())
		})
	}
}

func TestLoosenMissingCodeownersIsRed(t *testing.T) {
	h := prHost(nil, nil)
	delete(h.Files, "main:.github/CODEOWNERS")
	ok, err := loosenApproved(context.Background(), h, "origin/main", 7, &bytes.Buffer{})
	assert.False(t, ok)
	assert.ErrorIs(t, err, core.ErrNotFound)
}

// End to end: TIGHTEN needs no review; LOOSEN consults the (stubbed) hosting.
func TestPolicyCheckPR(t *testing.T) {
	prev := newHosting
	t.Cleanup(func() { newHosting = prev })
	restore := policy.SetCeilingPaths("/nonexistent/e.yaml", "/nonexistent/u.yaml")
	t.Cleanup(restore)
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")
	t.Setenv("GITHUB_REF", "refs/pull/7/merge")
	var h fakePR
	newHosting = func(string) (prHosting, error) { return h, nil }

	root := policyRepo(t)
	loosen := "risk:\n  hot_paths: [\"src/Payment/*.php\"]\nenforcement:\n  commands:\n    allow: [git status]\n"
	tighten := "risk:\n  hot_paths: [\"src/Payment/**\"]\nenforcement:\n  commands:\n    allow: []\n"

	writePolicy(t, root, tighten)
	h = prHost(nil, nil)
	_, err := runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.NoError(t, err, "TIGHTEN is green without review")

	writePolicy(t, root, loosen)
	var ee ExitError
	_, err = runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.True(t, errors.As(err, &ee), "LOOSEN without review is red")

	h = prHost([]core.Review{{Login: "bob", State: "APPROVED", CommitID: head}}, nil)
	_, err = runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.NoError(t, err, "LOOSEN with code-owner approval is green")

	h = prHost(nil, errors.New("API 500"))
	_, err = runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.Error(t, err, "API error is red")
}

func TestRemoteCheck(t *testing.T) {
	prev := newHosting
	t.Cleanup(func() { newHosting = prev })
	restore := policy.SetCeilingPaths("/nonexistent/e.yaml", "/nonexistent/u.yaml")
	t.Cleanup(restore)
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")

	good := `[{"type":"pull_request","parameters":{"require_code_owner_review":true,"dismiss_stale_reviews_on_push":true,"require_last_push_approval":true,"required_approving_review_count":1}},
	{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"rr-policy-check"}]}}]`
	tests := []struct {
		name      string
		rules     string
		codeowner string
		wantErr   bool
		wantOut   string
	}{
		{"complete", good, "riskrails.yaml @acme/owners\n", false, "remote ok"},
		{"no rules", `[]`, "riskrails.yaml @acme/owners\n", true, "L>=2 refused: missing"},
		{"bot code owner", good, "riskrails.yaml @acme/owners @rr-app[bot]\n", true, "bot identity"},
		{"no riskrails line", good, "src/ @acme/owners\n", true, "CODEOWNERS entry"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := prHost(nil, nil)
			h.Rules = json.RawMessage(tc.rules)
			h.Files["main:.github/CODEOWNERS"] = []byte(tc.codeowner)
			newHosting = func(string) (prHosting, error) { return h, nil }
			var out bytes.Buffer
			err := remoteCheck(context.Background(), "main", &out)
			assert.Equal(t, tc.wantErr, err != nil)
			assert.Contains(t, out.String(), tc.wantOut)
		})
	}
}
