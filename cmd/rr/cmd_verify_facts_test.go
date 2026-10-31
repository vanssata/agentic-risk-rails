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
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// startTask does what the flow does: baseline manifest file + task_started{scope, base_sha, baseline}.
func startTask(t *testing.T, root string, scope []string) {
	t.Helper()
	ctx := context.Background()
	manifest, sha, err := verify.Baseline(ctx, root)
	require.NoError(t, err)
	base, err := verify.HeadSHA(ctx, root)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(journal.RunDir(root), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(journal.RunDir(root), "t1.baseline.json"), manifest, 0o644))
	data, _ := json.Marshal(map[string]any{"scope": scope, "base_sha": base, "baseline": sha})
	_, err = journal.New(root).Append(ctx, core.Event{Type: "task_started", Task: "t1", Actor: core.ActorHuman, Data: data})
	require.NoError(t, err)
}

func TestVerifyFactsTrustsOnlyTheJournal(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")

	// the CLI has no way to supply scope or base
	for _, flag := range []string{"--scope", "--base"} {
		_, err := runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root, flag, "x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown flag")
	}

	// task_started without scope/base_sha/baseline: refuse
	_, err := journal.New(root).Append(context.Background(), core.Event{Type: "task_started", Task: "t1", Actor: core.ActorHuman, Data: json.RawMessage(`{}`)})
	require.NoError(t, err)
	_, err = runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing")
}

func TestVerifyFactsFromJournal(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")
	startTask(t, root, []string{"src/Payment/**"})

	// persistent flags: --task/--root work on the subcommand. No verify_run yet: facts fail,
	// but the answer is a verdict, not a refusal.
	out, err := runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close facts do not hold")
	assert.Contains(t, out, `"green_now": false`)
	assert.Contains(t, out, `"in_scope": true`)

	// an out-of-scope edit, even in an ignored-style path, is caught against the baseline
	require.NoError(t, os.WriteFile(filepath.Join(root, "src/Payment/PaymentService.php"), []byte("<?php // ok\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "poison.txt"), []byte("x"), 0o644))
	out, _ = runPolicyRR(t, "verify", "facts", "--task", "t1", "--root", root)
	assert.Contains(t, out, `"in_scope": false`)
	assert.Contains(t, out, "poison.txt")
	assert.NotContains(t, out, "PaymentService.php")
}
