package main

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestPolicyCheckRejectsAmbiguousBaseAndIndexGames(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{
		"riskrails.yaml": "risk:\n  hot_paths: [\"secrets/**\"]\n",
		"secrets/a":      "", "secrets/b": "",
	})
	gitIn := func(args ...string) {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	gitIn("update-ref", "refs/remotes/origin/main", "HEAD")
	gitIn("tag", "origin/main", "HEAD")
	_, err := runPolicyRR(t, "policy", "check", "--root", root, "--base", "origin/main")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous")

	// narrowing after removing a file from the index must not look like TIGHTEN
	gitIn("rm", "-q", "--cached", "secrets/b")
	writePolicy(t, root, "risk:\n  hot_paths: [\"secrets/a\"]\n")
	_, err = runPolicyRR(t, "policy", "check", "--root", root, "--base", "refs/remotes/origin/main")
	var ee ExitError
	require.True(t, errors.As(err, &ee))
}
