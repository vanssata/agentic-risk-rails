package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func runRR(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := cli.Root("test")
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func policyRepo(t *testing.T) string {
	return testutil.GitRepo(t, map[string]string{
		"riskrails.yaml":         "risk:\n  hot_paths: [\"src/Payment/**\"]\nenforcement:\n  commands:\n    allow: [git status]\n",
		"src/Payment/Charge.php": "",
		"src/Payment/Sub/A.php":  "",
	})
}

func writePolicy(t *testing.T, root, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), []byte(body), 0o644))
}

func TestPolicyCheckExitCodes(t *testing.T) {
	root := policyRepo(t)

	out, err := runRR(t, "policy", "check", "--root", root, "--base", "main")
	require.NoError(t, err)
	assert.Contains(t, out, "EQUAL")

	writePolicy(t, root, "risk:\n  hot_paths: [\"src/Payment/**\"]\nenforcement:\n  commands:\n    allow: []\n")
	out, err = runRR(t, "policy", "check", "--root", root, "--base", "main")
	require.NoError(t, err, out)
	assert.Contains(t, out, "TIGHTEN")

	writePolicy(t, root, "risk:\n  hot_paths: [\"src/Payment/*.php\"]\nenforcement:\n  commands:\n    allow: [git status]\n")
	out, err = runRR(t, "policy", "check", "--root", root, "--base", "main")
	var ee ExitError
	require.True(t, errors.As(err, &ee), "err=%v", err)
	assert.Equal(t, 1, ee.Code)
	assert.Contains(t, out, "LOOSEN")
	assert.Contains(t, out, "risk.hot_paths")

	// MIXED loosens too
	writePolicy(t, root, "risk:\n  hot_paths: [\"src/Payment/**\"]\nenforcement:\n  commands:\n    allow: [git status, rm x]\nautonomy:\n  unattended: {max_tasks_per_day: 1}\n")
	out, err = runRR(t, "policy", "check", "--root", root, "--base", "main")
	require.True(t, errors.As(err, &ee))
	assert.Contains(t, out, "MIXED")
}

func TestPolicyCheckInvalidOrUnknownBaseFails(t *testing.T) {
	root := policyRepo(t)
	writePolicy(t, root, "bogus: 1\n")
	_, err := runRR(t, "policy", "check", "--root", root, "--base", "main")
	require.Error(t, err)
	var ee ExitError
	assert.False(t, errors.As(err, &ee)) // main prints it and exits 1

	_, err = runRR(t, "policy", "check", "--root", root, "--base", "no-such-ref")
	assert.Error(t, err)
	_, err = runRR(t, "policy", "check", "--root", root)
	assert.Error(t, err, "--base is required")
}

func TestPolicyDiffJSON(t *testing.T) {
	root := policyRepo(t)
	writePolicy(t, root, "risk:\n  hot_paths: [\"src/Payment/*.php\"]\nenforcement:\n  commands:\n    allow: [git status]\n")
	out, err := runRR(t, "policy", "diff", "--root", root, "--base", "main", "--json")
	require.NoError(t, err, out) // diff reports, it does not fail on LOOSEN
	var got struct {
		Direction string
		Changes   []struct{ Path, Direction, Detail string }
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "LOOSEN", got.Direction)
	require.Len(t, got.Changes, 1)
	assert.Equal(t, "risk.hot_paths", got.Changes[0].Path)

	writePolicy(t, root, "risk:\n  hot_paths: [\"src/Payment/**\"]\nenforcement:\n  commands:\n    allow: [git status]\n")
	out, err = runRR(t, "policy", "diff", "--root", root, "--base", "main", "--json", "--file", "riskrails.yaml")
	require.NoError(t, err)
	assert.Contains(t, out, `"changes": []`)
}

func TestPolicyMissingCandidateFileIsStrictDefaults(t *testing.T) {
	root := policyRepo(t)
	require.NoError(t, os.Remove(filepath.Join(root, "riskrails.yaml")))
	out, err := runRR(t, "policy", "check", "--root", root, "--base", "main")
	var ee ExitError
	require.True(t, errors.As(err, &ee), out) // dropping hot_paths narrows the set
}
