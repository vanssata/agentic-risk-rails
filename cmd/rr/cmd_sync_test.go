package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
)

func TestSyncDisabledRuntimeFilesAreStale(t *testing.T) {
	orig := rrsync.InputProvider
	t.Cleanup(func() { rrsync.InputProvider = orig })
	root := t.TempDir()
	provider := func(rts []string) {
		rrsync.InputProvider = func(_ context.Context, r string) (core.SyncInput, error) {
			in := core.SyncInput{Root: r, Level: core.L1}
			in.Policy.Policy = core.StrictDefaults()
			in.Policy.Policy.Project.Runtimes = rts
			return in, nil
		}
	}
	ctx := context.Background()
	provider([]string{"claude", "codex"})
	_, err := runSelf(ctx, "sync", "--root", root)
	require.NoError(t, err)
	settings := filepath.Join(root, ".claude", "settings.json")
	require.FileExists(t, settings)

	provider([]string{"codex"})
	out, err := runSelf(ctx, "sync", "--check", "--root", root)
	require.Error(t, err, "stale manifest of a disabled runtime is red")
	assert.Contains(t, out, "stale (runtime disabled): .claude/settings.json")

	_, err = runSelf(ctx, "sync", "--root", root)
	require.NoError(t, err)
	assert.NoFileExists(t, settings)
	_, err = runSelf(ctx, "sync", "--check", "--root", root)
	require.NoError(t, err)
}

func TestSyncUnknownRuntimeFails(t *testing.T) {
	orig := rrsync.InputProvider
	t.Cleanup(func() { rrsync.InputProvider = orig })
	rrsync.InputProvider = func(_ context.Context, root string) (core.SyncInput, error) {
		in := core.SyncInput{Root: root, Level: core.L1}
		in.Policy.Policy.Project.Runtimes = []string{"Claude"}
		return in, nil
	}
	root := t.TempDir()
	for _, args := range [][]string{{"sync", "--root", root}, {"sync", "--check", "--root", root}} {
		out, err := runSelf(context.Background(), args...)
		require.Error(t, err, args)
		assert.Contains(t, out+err.Error(), `unknown runtime "Claude"`)
	}
}

// Committed manifests are checked in CI on another machine: rendering must not
// depend on $HOME (the fixture policy has ~ paths in secret_reads).
func TestSyncDoesNotDependOnHome(t *testing.T) {
	root := taskRepo(t)
	_, err := runPolicyRR(t, "sync", "--root", root)
	require.NoError(t, err)
	t.Setenv("HOME", t.TempDir())
	out, err := runPolicyRR(t, "sync", "--root", root, "--check")
	require.NoError(t, err, out)
}
