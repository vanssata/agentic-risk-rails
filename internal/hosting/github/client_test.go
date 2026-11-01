package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return b
}

// server serves synthetic responses; no real network is involved.
func server(t *testing.T) *Client {
	t.Helper()
	mux := http.NewServeMux()
	serve := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture(t, name))
		}
	}
	mux.HandleFunc("/repos/acme/shop/contents/riskrails.yaml", serve("contents.json"))
	mux.HandleFunc("/repos/acme/shop/contents/dir", serve("contents_dir.json"))
	mux.HandleFunc("/repos/acme/shop/pulls/7/reviews", serve("reviews.json"))
	mux.HandleFunc("/repos/acme/shop/pulls/7", serve("pull.json"))
	mux.HandleFunc("/repos/acme/shop/pulls/8/reviews", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	})
	mux.HandleFunc("/repos/acme/shop/rules/branches/main", serve("rules.json"))
	mux.HandleFunc("/orgs/acme/teams/owners/memberships/bob", serve("membership.json"))
	mux.HandleFunc("/repos/acme/shop/contents/boom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := New("acme/shop", "tok", srv.URL)
	require.NoError(t, err)
	return c
}

func TestReadFile(t *testing.T) {
	c := server(t)
	b, err := c.ReadFile(context.Background(), "main", "riskrails.yaml")
	require.NoError(t, err)
	assert.Equal(t, "schema: 1\n", string(b))

	_, err = c.ReadFile(context.Background(), "main", "missing.txt")
	assert.ErrorIs(t, err, core.ErrNotFound)

	_, err = c.ReadFile(context.Background(), "main", "boom")
	require.Error(t, err)
	assert.NotErrorIs(t, err, core.ErrNotFound, "5xx must not read as absent")

	_, err = c.ReadFile(context.Background(), "main", "dir")
	assert.Error(t, err)
}

func TestReviewsPullTeamRules(t *testing.T) {
	c := server(t)
	ctx := context.Background()

	rs, err := c.Reviews(ctx, 7)
	require.NoError(t, err)
	assert.Equal(t, []core.Review{
		{Login: "bob", State: "APPROVED", CommitID: "abc123"},
		{Login: "rr-app[bot]", State: "APPROVED", IsBot: true, CommitID: "abc123"},
	}, rs)

	_, err = c.Reviews(ctx, 8)
	assert.Error(t, err)

	pr, err := c.PullRequest(ctx, 7)
	require.NoError(t, err)
	assert.Equal(t, core.PullRequest{Number: 7, Author: "alice", URL: "https://example.test/pull/7", HeadSHA: "abc123"}, pr)

	ok, err := c.IsTeamMember(ctx, "owners", "bob")
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = c.IsTeamMember(ctx, "acme/owners", "nobody")
	require.NoError(t, err)
	assert.False(t, ok, "404 = not a member")

	raw, err := c.Rulesets(ctx, "main")
	require.NoError(t, err)
	missing, err := MissingRules(raw, "rr-policy-check")
	require.NoError(t, err)
	assert.Empty(t, missing)
	_, err = c.Rulesets(ctx, "nobranch")
	assert.Error(t, err)
}

func TestNewRejectsBadRemote(t *testing.T) {
	for _, r := range []string{"", "acme", "acme/", "/shop", "a/b/c"} {
		_, err := New(r, "", "")
		assert.Error(t, err, r)
	}
}

func TestTokenFromEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "g")
	t.Setenv("RR_GITHUB_TOKEN", "")
	assert.Equal(t, "g", TokenFromEnv())
	t.Setenv("RR_GITHUB_TOKEN", "r")
	assert.Equal(t, "r", TokenFromEnv())
}
