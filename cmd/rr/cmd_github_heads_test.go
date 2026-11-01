package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestLocalHeadsSecondParentOnlyInPullRequestRun(t *testing.T) {
	root := policyRepo(t)
	testutil.Git(t, root, "checkout", "-q", "-b", "side")
	require.NoError(t, os.WriteFile(filepath.Join(root, "x.txt"), []byte("x"), 0o644))
	testutil.Git(t, root, "add", "x.txt")
	testutil.Git(t, root, "commit", "-q", "-m", "side")
	testutil.Git(t, root, "checkout", "-q", "main")
	testutil.Git(t, root, "merge", "-q", "--no-ff", "-m", "merge", "side")

	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	heads, err := localHeads(context.Background(), root)
	require.NoError(t, err)
	assert.Len(t, heads, 1, "locally only HEAD counts")

	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	heads, err = localHeads(context.Background(), root)
	require.NoError(t, err)
	assert.Len(t, heads, 1)

	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	heads, err = localHeads(context.Background(), root)
	require.NoError(t, err)
	assert.Len(t, heads, 2, "merge ref in a pull_request run")
}

func TestPolicyFileMustBeRegular(t *testing.T) {
	root := policyRepo(t)
	require.NoError(t, os.Remove(filepath.Join(root, "riskrails.yaml")))
	require.NoError(t, os.Symlink("/proc/self/environ", filepath.Join(root, "riskrails.yaml")))
	out, err := runPolicyRR(t, "policy", "check", "--root", root, "--base", "main")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
	assert.NotContains(t, out, "PATH=")
}
