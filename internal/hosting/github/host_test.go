package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// pushFixture: a source repo with rr/x, a tag and main, and an empty bare target.
func pushFixture(t *testing.T) (c *Client, src, target string) {
	t.Helper()
	src = testutil.GitRepo(t, map[string]string{"a": "1"})
	testutil.Git(t, src, "branch", "rr/x")
	testutil.Git(t, src, "tag", "v9")
	target = t.TempDir()
	testutil.Git(t, target, "init", "-q", "--bare")
	c, err := newAt("acme/shop", "tok", "")
	require.NoError(t, err)
	c.pushURL = "file://" + target
	return c, src, target
}

func targetRefs(t *testing.T, target string) []string {
	t.Helper()
	return strings.Fields(testutil.Git(t, target, "for-each-ref", "--format=%(refname)"))
}

func TestPushCreatesOnlyBranch(t *testing.T) {
	c, src, target := pushFixture(t)
	require.NoError(t, c.Push(context.Background(), src, "rr/x"))
	assert.Equal(t, []string{"refs/heads/rr/x"}, targetRefs(t, target))
}

func TestPushIgnoresPoisonedSourceConfig(t *testing.T) {
	c, src, target := pushFixture(t)
	testutil.Git(t, src, "config", "push.followTags", "true")
	testutil.Git(t, src, "config", "push.gpgSign", "true")
	testutil.Git(t, src, "config", "push.pushOption", "x=y")
	testutil.Git(t, src, "config", "http.proxy", "http://127.0.0.1:1")
	testutil.Git(t, src, "config", "url.https://evil/.insteadOf", "file://")
	testutil.Git(t, src, "config", "protocol.allow", "never")
	testutil.Git(t, src, "config", "core.hooksPath", filepath.Join(src, "hooks"))
	testutil.Git(t, src, "config", "extensions.worktreeConfig", "true")
	require.NoError(t, os.WriteFile(filepath.Join(src, ".git", "config.worktree"),
		[]byte("[http]\n\tproxy = http://127.0.0.1:1\n[url \"https://evil/\"]\n\tinsteadOf = file://\n[push]\n\tfollowTags = true\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(src, "hooks"), 0o755))
	marker := filepath.Join(t.TempDir(), "ran")
	require.NoError(t, os.WriteFile(filepath.Join(src, "hooks", "pre-push"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755))

	require.NoError(t, c.Push(context.Background(), src, "rr/x"))
	assert.Equal(t, []string{"refs/heads/rr/x"}, targetRefs(t, target), "no tags")
	assert.NoFileExists(t, marker)
}

func TestPushRefusesForeignObjects(t *testing.T) {
	c, src, _ := pushFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(src, ".git", "objects", "info", "alternates"), []byte("/tmp/other/objects\n"), 0o644))
	err := c.Push(context.Background(), src, "rr/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refused")

	c, src, _ = pushFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(src, ".git", "commondir"), []byte("../x\n"), 0o644))
	assert.Error(t, c.Push(context.Background(), src, "rr/x"))

	// a .git file (linked worktree) is refused too
	c, src, _ = pushFixture(t)
	other := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other, ".git"), []byte("gitdir: "+filepath.Join(src, ".git")+"\n"), 0o644))
	assert.Error(t, c.Push(context.Background(), other, "rr/x"))
}

func TestPushRefusesSymlinks(t *testing.T) {
	foreign := testutil.GitRepo(t, map[string]string{"secret": "TOPSECRET"})
	testutil.Git(t, foreign, "branch", "rr/v")
	for name, mutate := range map[string]func(t *testing.T, src string){
		"dot-git": func(t *testing.T, src string) {
			require.NoError(t, os.RemoveAll(filepath.Join(src, ".git")))
			require.NoError(t, os.Symlink(filepath.Join(foreign, ".git"), filepath.Join(src, ".git")))
		},
		"objects": func(t *testing.T, src string) {
			require.NoError(t, os.RemoveAll(filepath.Join(src, ".git", "objects")))
			require.NoError(t, os.Symlink(filepath.Join(foreign, ".git", "objects"), filepath.Join(src, ".git", "objects")))
		},
		"loose-dir": func(t *testing.T, src string) {
			require.NoError(t, os.MkdirAll(filepath.Join(src, ".git", "objects", "ab"), 0o755))
			require.NoError(t, os.RemoveAll(filepath.Join(src, ".git", "objects", "pack")))
			require.NoError(t, os.Symlink(filepath.Join(foreign, ".git", "objects", "pack"), filepath.Join(src, ".git", "objects", "pack")))
		},
		"ref": func(t *testing.T, src string) {
			require.NoError(t, os.Remove(filepath.Join(src, ".git", "refs", "heads", "rr", "x")))
			require.NoError(t, os.Symlink(filepath.Join(foreign, ".git", "refs", "heads", "rr", "v"), filepath.Join(src, ".git", "refs", "heads", "rr", "x")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, src, target := pushFixture(t)
			mutate(t, src)
			err := c.Push(context.Background(), src, "rr/x")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "refused")
			assert.Empty(t, targetRefs(t, target))
		})
	}
}

func TestPushFetchTimeConfigRunsNothing(t *testing.T) {
	c, src, target := pushFixture(t)
	marker := filepath.Join(t.TempDir(), "ran")
	script := filepath.Join(t.TempDir(), "x.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755))
	hooks := filepath.Join(src, "hooks")
	require.NoError(t, os.MkdirAll(hooks, 0o755))
	for _, h := range []string{"pre-upload-pack", "reference-transaction", "post-fetch", "pre-auto-gc"} {
		require.NoError(t, os.WriteFile(filepath.Join(hooks, h), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755))
	}
	testutil.Git(t, src, "config", "core.fsmonitor", script)
	testutil.Git(t, src, "config", "core.hooksPath", hooks)
	testutil.Git(t, src, "config", "uploadpack.packObjectsHook", script)
	testutil.Git(t, src, "config", "core.gitProxy", script)
	testutil.Git(t, src, "config", "core.sshCommand", script)
	testutil.Git(t, src, "config", "core.alternateRefsCommand", script)
	require.NoError(t, c.Push(context.Background(), src, "rr/x"))
	assert.Equal(t, []string{"refs/heads/rr/x"}, targetRefs(t, target))
	assert.NoFileExists(t, marker)
}

func TestPushMissingBranchFails(t *testing.T) {
	c, src, target := pushFixture(t)
	assert.Error(t, c.Push(context.Background(), src, "rr/nope"))
	assert.Empty(t, targetRefs(t, target))
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
