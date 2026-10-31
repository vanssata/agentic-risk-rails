package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// server answers per model name; the body of the request carries "model".
func server(t *testing.T, wantPath, wantHeader string, answers map[string]struct {
	status int
	body   string
}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, wantPath, r.URL.Path)
		assert.NotEmpty(t, r.Header.Get(wantHeader))
		var b map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
		if v, ok := b["max_tokens"]; ok {
			assert.EqualValues(t, 1, v)
		} else {
			assert.EqualValues(t, 1, b["max_completion_tokens"])
		}
		a := answers[b["model"].(string)]
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	}))
}

type ans = struct {
	status int
	body   string
}

func TestHTTPProberAnthropic(t *testing.T) {
	errBody := func(typ string) string { return `{"type":"error","error":{"type":"` + typ + `","message":"x"}}` }
	srv := server(t, "/v1/messages", "x-api-key", map[string]ans{
		"ok":   {200, `{"id":"m","content":[]}`},
		"perm": {403, errBody("permission_error")},
		"nf":   {404, errBody("not_found_error")},
		"rl":   {429, errBody("rate_limit_error")},
		"ov":   {529, errBody("overloaded_error")},
		"bad":  {400, errBody("invalid_request_error")},
		"auth": {401, errBody("authentication_error")},
		"5xx":  {500, `oops`},
	})
	defer srv.Close()
	rs, err := HTTPProber{Kind: Anthropic, BaseURL: srv.URL, Key: "k"}.Probe(context.Background(),
		[]string{"ok", "perm", "nf", "rl", "ov", "bad", "auth", "5xx"})
	require.NoError(t, err)
	got := map[string]core.ModelState{}
	for _, r := range rs {
		got[r.Model] = r.State
	}
	assert.Equal(t, map[string]core.ModelState{
		"ok": core.ModelPass, "perm": core.ModelFail, "nf": core.ModelFail, "rl": core.ModelUnknown,
		"ov": core.ModelUnknown, "bad": core.ModelUnknown, "auth": core.ModelFail, "5xx": core.ModelUnknown,
	}, got)
	assert.Equal(t, "permission_error", rs[1].Error)
}

func TestHTTPProberOpenAIAndOpenRouter(t *testing.T) {
	oa := server(t, "/v1/chat/completions", "Authorization", map[string]ans{
		"ok":    {200, `{"choices":[]}`},
		"gone":  {404, `{"error":{"message":"x","type":"invalid_request_error","code":"model_not_found"}}`},
		"quota": {429, `{"error":{"type":"insufficient_quota","code":"insufficient_quota"}}`},
		"deny":  {403, `{"error":{"message":"x"}}`},
	})
	defer oa.Close()
	rs, _ := HTTPProber{Kind: OpenAI, BaseURL: oa.URL, Key: "k"}.Probe(context.Background(), []string{"ok", "gone", "quota", "deny"})
	assert.Equal(t, []core.ModelState{core.ModelPass, core.ModelFail, core.ModelUnknown, core.ModelFail},
		[]core.ModelState{rs[0].State, rs[1].State, rs[2].State, rs[3].State})

	or := server(t, "/api/v1/chat/completions", "Authorization", map[string]ans{
		"ok":   {200, `{"choices":[]}`},
		"nf":   {404, `{"error":{"code":404,"message":"No endpoints found"}}`},
		"rl":   {429, `{"error":{"code":429,"message":"slow"}}`},
		"auth": {401, `{"error":{"code":401,"message":"Missing Authentication header"}}`},
	})
	defer or.Close()
	rs, _ = HTTPProber{Kind: OpenRouter, BaseURL: or.URL, Key: "k"}.Probe(context.Background(), []string{"ok", "nf", "rl", "auth"})
	assert.Equal(t, []core.ModelState{core.ModelPass, core.ModelFail, core.ModelUnknown, core.ModelFail},
		[]core.ModelState{rs[0].State, rs[1].State, rs[2].State, rs[3].State})
	assert.Equal(t, "http_404", rs[1].Error)
}

func TestClassifySuccessNeedsCompletionShape(t *testing.T) {
	cases := []struct {
		kind, body string
		want       core.ModelState
	}{
		{Anthropic, `{"content":[]}`, core.ModelPass},
		{OpenAI, `{"choices":[]}`, core.ModelPass},
		{Anthropic, `{}`, core.ModelUnknown},
		{Anthropic, `<html>proxy</html>`, core.ModelUnknown},
		{Anthropic, `{"choices":[]}`, core.ModelUnknown},
		{OpenRouter, `{"error":{"code":402},"choices":[]}`, core.ModelUnknown},
		{OpenAI, ``, core.ModelUnknown},
	}
	for _, c := range cases {
		got, _ := Classify(c.kind, 200, []byte(c.body))
		assert.Equal(t, c.want, got, c.kind+" "+c.body)
	}
}

func TestHTTPProberDoesNotFollowRedirectsAndCapsError(t *testing.T) {
	leaked := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("x-api-key") != "" }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			http.Redirect(w, r, other.URL+"/x", http.StatusTemporaryRedirect)
			return
		}
	}))
	defer srv.Close()
	rs, _ := HTTPProber{Kind: Anthropic, BaseURL: srv.URL, Key: "k"}.Probe(context.Background(), []string{"m"})
	assert.False(t, leaked)
	assert.NotEqual(t, core.ModelPass, rs[0].State)

	long := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"type":"` + strings.Repeat("x", 1000) + `"}}`))
	}))
	defer long.Close()
	rs, _ = HTTPProber{Kind: Anthropic, BaseURL: long.URL, Key: "k"}.Probe(context.Background(), []string{"m"})
	assert.Len(t, rs[0].Error, 128)
}

func TestHTTPProberNetworkErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	rs, err := HTTPProber{Kind: Anthropic, BaseURL: url, Key: "k"}.Probe(context.Background(), []string{"m"})
	require.NoError(t, err)
	assert.Equal(t, core.ModelUnknown, rs[0].State)
}

func TestCLIProber(t *testing.T) {
	bin := testutil.FakeBin(t, "fakeclaude", `
model=""
while [ $# -gt 0 ]; do [ "$1" = "--model" ] && model="$2"; shift; done
case "$model" in
  sonnet) echo ok; exit 0;;
  fable) echo "There's an issue with the selected model (fable). It may not exist or you may not have access to it." >&2; exit 1;;
  org) echo "model restricted by your organization" >&2; exit 1;;
  *) echo boom >&2; exit 3;;
esac`)
	rs, err := CLIProber{Name: "claude", Bin: bin}.Probe(context.Background(), []string{"sonnet", "fable", "org", "weird"})
	require.NoError(t, err)
	assert.Equal(t, []core.ModelState{core.ModelPass, core.ModelFail, core.ModelFail, core.ModelUnknown},
		[]core.ModelState{rs[0].State, rs[1].State, rs[2].State, rs[3].State})
}

func TestCLIProberRejects(t *testing.T) {
	ctx := context.Background()
	_, err := CLIProber{Name: "claude", Bin: "claude"}.Probe(ctx, []string{"--dangerous"})
	assert.Error(t, err)
	_, err = CLIProber{Name: "claude", Bin: "-x"}.Probe(ctx, []string{"sonnet"})
	assert.Error(t, err)
	_, err = CLIProber{Name: "codex", Bin: "codex"}.Probe(ctx, []string{"gpt-5"})
	assert.Error(t, err)
}

func TestCLIProberRunsInTempDir(t *testing.T) {
	bin := testutil.FakeBin(t, "fakeclaude", `pwd >&2; case "$(pwd)" in "$RR_REPO"*) exit 1;; esac; echo ok`)
	wd, _ := os.Getwd()
	t.Setenv("RR_REPO", wd)
	rs, err := CLIProber{Name: "claude", Bin: bin}.Probe(context.Background(), []string{"sonnet"})
	require.NoError(t, err)
	assert.Equal(t, core.ModelPass, rs[0].State)
}

func TestCLIProberMissingBinaryIsNotPass(t *testing.T) {
	rs, _ := CLIProber{Name: "claude", Bin: "/nonexistent/claude"}.Probe(context.Background(), []string{"sonnet"})
	assert.NotEqual(t, core.ModelPass, rs[0].State)
	assert.False(t, strings.Contains(rs[0].Error, " "))
}

func TestProfileProber(t *testing.T) {
	rs, _ := ProfileProber{Name: "claude", Exclude: []string{"fable"}}.Probe(context.Background(), []string{"sonnet", "fable"})
	assert.Equal(t, core.ModelPass, rs[0].State)
	assert.Equal(t, core.ModelFail, rs[1].State)
}
