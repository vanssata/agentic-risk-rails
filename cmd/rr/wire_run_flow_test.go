package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/flow"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// Start and Close of a runner task go through the real internal/flow: the journal
// and baseline live in the state dir, nothing is written under the checkout's .rr,
// and the verify adapters' commands run through the container sandbox.
func TestRunFlowStartCloseThroughRealFlow(t *testing.T) {
	restore := policy.SetCeilingPaths(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "none"))
	defer restore()
	repo := testutil.CopyFixture(t, "php-symfony")
	state := t.TempDir()
	r, err := resolve(t.Context(), repo)
	require.NoError(t, err)
	tiers := core.EffectiveTiers{Runtime: "claude", Models: map[core.Tier]string{core.TierBalanced: "m"}}
	start, closeTask := runFlow(runFlowIn{Root: repo, StateRoot: state, Home: t.TempDir(), Policy: r.eff, Tiers: tiers})

	require.Error(t, start(t.Context(), autonomy.Task{ID: "t1", Brief: "x"}), "no files, no scope for the hook")
	require.NoError(t, start(t.Context(), autonomy.Task{ID: "t1", Brief: "fix a typo in the notes", Files: []string{"docs/notes.md"}}))

	var calls [][]string
	sb := func(argv []string) ([]string, error) {
		calls = append(calls, argv)
		return append([]string{"sh", "-c", "exit 0", "--"}, argv...), nil
	}
	ctx := verify.WithSandbox(context.Background(), sb)
	require.NoError(t, closeTask(ctx, "t1"))
	assert.NotEmpty(t, calls, "adapter commands go through the sandbox")

	_, err = os.Stat(filepath.Join(repo, ".rr"))
	assert.True(t, os.IsNotExist(err), "nothing under the checkout's .rr")
	m, _ := filepath.Glob(filepath.Join(state, ".rr", "*", "t1*"))
	assert.NotEmpty(t, m, "journal and baseline are under the state dir")
}

// The scope file the runner writes (a JSON array of repo-relative paths, outside the
// checkout) is what the in-container hook reads.
func TestRunnerScopeFileFormatMatchesTheHook(t *testing.T) {
	repo := t.TempDir()
	f := filepath.Join(t.TempDir(), autonomy.ScopeFileName)
	require.NoError(t, os.WriteFile(f, []byte(`["docs/notes.md","src/**/*.php"]`), 0o600))
	got, armed, err := flow.ScopeFromEnv(repo, []string{"src/a/B.php"}, core.L2, func(string) (string, bool) { return f, true })
	require.NoError(t, err)
	assert.True(t, armed)
	assert.Equal(t, []string{"docs/notes.md", "src/a/B.php"}, got)
}
