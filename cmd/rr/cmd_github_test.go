package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

type fakePR struct {
	*fakes.Hosting
	pr         core.PullRequest
	reviewsErr error
	bypass     []string
	bypassErr  error
}

func (f fakePR) PullRequest(context.Context, int) (core.PullRequest, error) { return f.pr, nil }

func (f fakePR) BypassActors(context.Context, json.RawMessage) ([]string, error) {
	return f.bypass, f.bypassErr
}

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
		pr:         core.PullRequest{Number: 7, Author: "alice", HeadSHA: head, Base: "main"},
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
			ok, err := loosenApproved(context.Background(), prHost(tc.reviews, tc.revErr), "origin/main", tc.n, []string{head}, &out)
			assert.Equal(t, tc.wantErr, err != nil)
			assert.Equal(t, tc.want, ok, out.String())
		})
	}
}

func TestLoosenMissingCodeownersIsRed(t *testing.T) {
	h := prHost(nil, nil)
	delete(h.Files, "main:.github/CODEOWNERS")
	ok, err := loosenApproved(context.Background(), h, "origin/main", 7, []string{head}, &bytes.Buffer{})
	assert.False(t, ok)
	assert.ErrorIs(t, err, core.ErrNotFound)
}

// End to end: TIGHTEN needs no review; LOOSEN consults the (stubbed) hosting.
func TestPolicyCheckPR(t *testing.T) {
	prev := newHosting
	t.Cleanup(func() { newHosting = prev })
	restore := policy.SetCeilingPaths("/nonexistent/e.yaml", "/nonexistent/u.yaml")
	t.Cleanup(restore)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")
	t.Setenv("GITHUB_REF", "refs/pull/7/merge")
	var h fakePR
	newHosting = func(string) (prHosting, error) { return h, nil }

	root := policyRepo(t)
	loosen := "risk:\n  hot_paths: [\"src/Payment/*.php\"]\nenforcement:\n  commands:\n    allow: [git status]\n"
	tighten := "risk:\n  hot_paths: [\"src/Payment/**\"]\nenforcement:\n  commands:\n    allow: []\n"

	sha := strings.TrimSpace(testutil.Git(t, root, "rev-parse", "HEAD"))
	host := func(rs []core.Review, err error) fakePR {
		h := prHost(rs, err)
		h.pr.HeadSHA = sha
		return h
	}

	writePolicy(t, root, tighten)
	h = host(nil, nil)
	_, err := runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.NoError(t, err, "TIGHTEN is green without review")

	writePolicy(t, root, loosen)
	var ee ExitError
	_, err = runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.True(t, errors.As(err, &ee), "LOOSEN without review is red")

	h = host([]core.Review{{Login: "bob", State: "APPROVED", CommitID: sha}}, nil)
	_, err = runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.NoError(t, err, "LOOSEN with code-owner approval is green")

	h = host(nil, errors.New("API 500"))
	_, err = runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.Error(t, err, "API error is red")
}

func TestRemoteCheck(t *testing.T) {
	prev := newHosting
	t.Cleanup(func() { newHosting = prev })
	restore := policy.SetCeilingPaths("/nonexistent/e.yaml", "/nonexistent/u.yaml")
	t.Cleanup(restore)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")

	good := `[{"type":"pull_request","parameters":{"require_code_owner_review":true,"dismiss_stale_reviews_on_push":true,"require_last_push_approval":true,"required_approving_review_count":1}},
	{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"rr-policy-check","integration_id":15368}]}}]`
	tests := []struct {
		name      string
		rules     string
		codeowner string
		bypass    []string
		bypassErr error
		wantErr   bool
		wantOut   string
	}{
		{"complete", good, "riskrails.yaml @acme/owners\n", nil, nil, false, "remote ok"},
		{"no rules", `[]`, "riskrails.yaml @acme/owners\n", nil, nil, true, "L>=2 refused: missing"},
		{"bot code owner", good, "riskrails.yaml @acme/owners @rr-app[bot]\n", nil, nil, true, "bot identity"},
		{"bypass actor", good, "riskrails.yaml @acme/owners\n", []string{"ruleset 1: RepositoryRole 5"}, nil, true, "empty bypass_actors"},
		{"bypass unverifiable", good, "riskrails.yaml @acme/owners\n", nil, errors.New("403"), true, ""},
		{"no riskrails line", good, "src/ @acme/owners\n", nil, nil, true, "CODEOWNERS entry"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := prHost(nil, nil)
			h.Rules = json.RawMessage(tc.rules)
			h.bypass, h.bypassErr = tc.bypass, tc.bypassErr
			h.Files["main:.github/CODEOWNERS"] = []byte(tc.codeowner)
			newHosting = func(string) (prHosting, error) { return h, nil }
			var out bytes.Buffer
			err := remoteCheck(context.Background(), "main", &out)
			assert.Equal(t, tc.wantErr, err != nil)
			assert.Contains(t, out.String(), tc.wantOut)
		})
	}
}

func TestLoosenRejectsWrongBaseOrHead(t *testing.T) {
	appr := []core.Review{{Login: "bob", State: "APPROVED", CommitID: head}}
	h := prHost(appr, nil)
	ctx := context.Background()

	h.pr.Base = "other"
	ok, err := loosenApproved(ctx, h, "origin/main", 7, []string{head}, &bytes.Buffer{})
	require.NoError(t, err)
	assert.False(t, ok, "PR targets another branch")

	h = prHost(appr, nil)
	ok, err = loosenApproved(ctx, h, "origin/main", 7, []string{"unrelated"}, &bytes.Buffer{})
	require.NoError(t, err)
	assert.False(t, ok, "checkout is not the PR head")

	ok, err = loosenApproved(ctx, h, "upstream/main", 7, []string{head}, &bytes.Buffer{})
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestBranchOf(t *testing.T) {
	for in, want := range map[string]string{"main": "main", "origin/main": "main", "refs/remotes/origin/main": "main", "refs/heads/dev": "dev"} {
		got, err := branchOf(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}
	for _, in := range []string{"", "upstream/main", "origin/"} {
		_, err := branchOf(in)
		assert.Error(t, err, in)
	}
}

// Env is trusted only inside GitHub Actions; the enterprise ceiling wins over the user one.
func TestRemoteRepoSources(t *testing.T) {
	dir := t.TempDir()
	ent, user := filepath.Join(dir, "e.yaml"), filepath.Join(dir, "u.yaml")
	t.Cleanup(policy.SetCeilingPaths(ent, user))
	t.Setenv("GITHUB_REPOSITORY", "evil/fake")
	t.Setenv("GITHUB_ACTIONS", "")
	_, err := remoteRepo()
	assert.Error(t, err, "env ignored outside Actions")

	require.NoError(t, os.WriteFile(user, []byte("remote: user/repo\n"), 0o644))
	got, err := remoteRepo()
	require.NoError(t, err)
	assert.Equal(t, "user/repo", got)

	require.NoError(t, os.WriteFile(ent, []byte("remote: ent/repo\n"), 0o644))
	got, err = remoteRepo()
	require.NoError(t, err)
	assert.Equal(t, "ent/repo", got)

	t.Cleanup(policy.SetCeilingPaths(filepath.Join(dir, "none1"), filepath.Join(dir, "none2")))
	t.Setenv("GITHUB_ACTIONS", "true")
	got, err = remoteRepo()
	require.NoError(t, err)
	assert.Equal(t, "evil/fake", got, "inside Actions the env repo is used")
}
