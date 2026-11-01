package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

func TestRunHostingNeedsCeilingRemote(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "ceiling.yaml")
	restore := policy.SetCeilingPaths(filepath.Join(dir, "none"), user)
	defer restore()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "evil/repo")
	_, err := runHosting(context.Background(), dir)
	require.ErrorContains(t, err, "no remote pinned")

	require.NoError(t, os.WriteFile(user, []byte("remote: acme/shop\n"), 0o600))
	h, err := runHosting(context.Background(), dir)
	require.NoError(t, err)
	require.NotNil(t, h)
}
