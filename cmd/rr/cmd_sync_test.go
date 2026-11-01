package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
)

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
