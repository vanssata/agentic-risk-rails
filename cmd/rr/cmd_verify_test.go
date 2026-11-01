package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestVerifyUsesResolvedPolicy(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")
	// a working copy that empties full_run_when must not loosen the resolved policy
	raw, err := os.ReadFile(filepath.Join(root, "riskrails.yaml"))
	require.NoError(t, err)
	var loosened []byte
	for _, l := range splitLinesKeep(string(raw)) {
		if len(l) > 17 && l[:17] == "  full_run_when:" {
			l = "  full_run_when: []\n"
		}
		loosened = append(loosened, l...)
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), loosened, 0o644))

	startTaskMode(t, root, "full")
	out, err := runPolicyRR(t, "affected", "--root", root, "--phpunit", "--task", "t1", "src/Payment/PaymentService.php")
	require.NoError(t, err)
	var got struct{ Full bool }
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.True(t, got.Full, "mode>=full still forces a full run under the in-force policy")

	// an unparsable policy refuses instead of falling back
	require.NoError(t, os.WriteFile(filepath.Join(root, "riskrails.yaml"), []byte("verify: [\n"), 0o644))
	_, err = runPolicyRR(t, "affected", "--root", root, "--phpunit", "x.php")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing")
}

func splitLinesKeep(s string) []string {
	var out []string
	start := 0
	for i := range s {
		if s[i] == '\n' {
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func TestVerifyFullWithoutTask(t *testing.T) {
	root := taskRepo(t)
	out, err := runPolicyRR(t, "verify", "--root", root, "--full")
	require.NoError(t, err, out)
	var rep struct{ Full, Passed bool }
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.True(t, rep.Full && rep.Passed, out)
	_, statErr := os.Stat(filepath.Join(root, ".rr", "run"))
	assert.True(t, os.IsNotExist(statErr), "a CI full run writes no journal")

	testutil.FakeBin(t, "php", "exit 1")
	_, err = runPolicyRR(t, "verify", "--root", root, "--full")
	require.Error(t, err, "red suite ⇒ red check")

	for _, args := range [][]string{{"verify", "--root", root}, {"verify", "--root", root, "--full", "--task", "t1"}} {
		_, err = runPolicyRR(t, args...)
		require.ErrorContains(t, err, "exactly one of", "%v", args)
	}
}
