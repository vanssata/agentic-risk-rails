package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func apiClient(t *testing.T, labelStatus int, calls *[]string) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/shop/pulls", func(w http.ResponseWriter, r *http.Request) {
		*calls = append(*calls, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":9,"html_url":"https://x/9","head":{"sha":"abc"},"base":{"ref":"main"},"user":{"login":"rr"}}`))
	})
	mux.HandleFunc("/repos/acme/shop/issues/9/labels", func(w http.ResponseWriter, r *http.Request) {
		var got []string
		_ = json.NewDecoder(r.Body).Decode(&got)
		*calls = append(*calls, r.Method+" "+r.URL.Path+" "+strings.Join(got, ","))
		if labelStatus != http.StatusOK {
			http.Error(w, `{"message":"no"}`, labelStatus)
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})
	// the branch is one escaped path segment (rr%2Fok); r.URL.Path is decoded
	mux.HandleFunc("/repos/acme/shop/branches/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/shop/branches/rr/ok":
			_, _ = w.Write([]byte(`{"name":"rr/ok","commit":{"sha":"deadbeef"}}`))
		case "/repos/acme/shop/branches/rr/boom":
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		default:
			http.Error(w, `{"message":"Branch not found"}`, http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := newAt("acme/shop", "tok", srv.URL)
	require.NoError(t, err)
	return c
}

func TestOpenDraftPRLabels(t *testing.T) {
	var calls []string
	c := apiClient(t, http.StatusOK, &calls)
	pr, err := c.OpenDraftPR(context.Background(), "rr/a", "main", "t", "b", []string{"rr", "bot"})
	require.NoError(t, err)
	assert.Equal(t, 9, pr.Number)
	assert.Equal(t, []string{"POST /repos/acme/shop/pulls", "POST /repos/acme/shop/issues/9/labels rr,bot"}, calls)

	calls = nil
	_, err = c.OpenDraftPR(context.Background(), "rr/a", "main", "t", "b", nil)
	require.NoError(t, err)
	assert.Len(t, calls, 1, "no labels, no second request")
}

func TestOpenDraftPRLabelFailureMentionsPR(t *testing.T) {
	var calls []string
	c := apiClient(t, http.StatusUnprocessableEntity, &calls)
	_, err := c.OpenDraftPR(context.Background(), "rr/a", "main", "t", "b", []string{"rr"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "#9")
	assert.Len(t, calls, 2, "the PR is not closed")
}

func TestBranchSHA(t *testing.T) {
	var calls []string
	c := apiClient(t, http.StatusOK, &calls)
	sha, err := c.BranchSHA(context.Background(), "rr/ok")
	require.NoError(t, err)
	assert.Equal(t, "deadbeef", sha)

	_, err = c.BranchSHA(context.Background(), "rr/missing")
	assert.ErrorIs(t, err, core.ErrNotFound)

	_, err = c.BranchSHA(context.Background(), "rr/boom")
	require.Error(t, err)
	assert.NotErrorIs(t, err, core.ErrNotFound)
}

func TestPushRefusesBadBranches(t *testing.T) {
	c, err := newAt("acme/shop", "tok", "")
	require.NoError(t, err)
	root := testutil.GitRepo(t, map[string]string{"a": "1"})
	for _, b := range []string{
		"main", "", "rr", "rr/", "-rr/x", "rr/../main", "rr/a b", "rr/a:b", "+rr/x", "rr/x:refs/heads/main",
		"rr/a..b", "rr/x.lock", "rr/a~1", "rr/a^", "rr/a@{1}", "rr/a\\b", "rr/a?", "rr/a*", "rr//x", "rr/x/", "rr/--force",
	} {
		assert.Error(t, c.Push(context.Background(), root, b), "branch %q", b)
	}
	noTok, err := newAt("acme/shop", "", "")
	require.NoError(t, err)
	assert.Error(t, noTok.Push(context.Background(), root, "rr/ok"))
}

func TestPushRefusesPoisonedConfig(t *testing.T) {
	c, err := newAt("acme/shop", "tok", "")
	require.NoError(t, err)
	for _, kv := range [][2]string{
		{"url.https://evil/.insteadOf", "https://github.com/"},
		{"http.proxy", "http://evil:1"},
		{"include.path", "/tmp/x"},
	} {
		root := testutil.GitRepo(t, map[string]string{"a": "1"})
		testutil.Git(t, root, "config", kv[0], kv[1])
		err := c.Push(context.Background(), root, "rr/ok")
		require.Error(t, err, kv[0])
		assert.Contains(t, err.Error(), "refused")
	}
}

func TestPushCmdTokenOnlyInEnv(t *testing.T) {
	c, err := newAt("acme/shop", "s3cr3t-token", "")
	require.NoError(t, err)
	cmd := c.pushCmd(context.Background(), "/repo", "rr/ok")

	argv := strings.Join(cmd.Args, "\x00")
	assert.NotContains(t, argv, "s3cr3t-token")
	assert.NotContains(t, argv, "x-access-token")
	assert.NotContains(t, argv, "AUTHORIZATION")
	assert.NotContains(t, argv, "--force")
	assert.Contains(t, cmd.Args, "https://github.com/acme/shop.git")
	assert.Contains(t, cmd.Args, "refs/heads/rr/ok:refs/heads/rr/ok")
	assert.Contains(t, cmd.Args, "core.hooksPath=/dev/null")
	assert.Contains(t, cmd.Args, "--no-verify")
	for _, a := range cmd.Args {
		assert.False(t, strings.HasPrefix(a, "+") || strings.Contains(a, ":+"), a)
	}

	env := strings.Join(cmd.Env, "\n")
	assert.Contains(t, env, "GIT_CONFIG_COUNT=1")
	assert.Contains(t, env, "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader")
	assert.Contains(t, env, "GIT_CONFIG_VALUE_0=AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46czNjcjN0LXRva2Vu")
	assert.NotContains(t, env, "s3cr3t-token", "token is only base64 in the header value")
}
