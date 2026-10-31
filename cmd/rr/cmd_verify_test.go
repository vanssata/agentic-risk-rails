package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func startTask(t *testing.T, root string, data string) {
	t.Helper()
	_, err := journal.New(root).Append(context.Background(), core.Event{Type: "task_started", Task: "t1", Actor: core.ActorHuman, Data: json.RawMessage(data)})
	require.NoError(t, err)
}

func TestVerifyFactsFlagsAndScope(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")

	// persistent flags: --task/--root work on the subcommand; no scope anywhere => refuse
	startTask(t, root, `{}`)
	_, err := runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no scope in the task journal")

	// --scope without a terminal is refused too (an agent has no TTY)
	_, err = runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root, "--scope", "**")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interactive terminal")
}

func TestVerifyFactsScopeFromJournal(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")
	startTask(t, root, `{"scope":["src/**"]}`)

	_, err := runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root, "--scope", "**")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already carries a scope")

	// scope is known; no verify_run yet => facts do not hold, but the refusal is about facts
	out, err := runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close facts do not hold")
	assert.Contains(t, out, `"green_now": false`)
}

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

	out, err := runPolicyRR(t, "affected", "--root", root, "--phpunit", "--mode", "full", "src/Payment/PaymentService.php")
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
