package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// Regression (wave-1 round 3 BLOCKER): a poisoned repo config must not make
// rr's git calls execute a program on the host.
func TestGitOutIgnoresExecutingConfig(t *testing.T) {
	repo := testutil.GitRepo(t, map[string]string{"riskrails.yaml": "schema: 1\n", "a.txt": "x"})
	marker := filepath.Join(t.TempDir(), "pwned")
	script := filepath.Join(t.TempDir(), "evil.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho pwned >> "+marker+"\n"), 0o755))
	f, err := os.OpenFile(filepath.Join(repo, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString("[core]\n\tfsmonitor = " + script + "\n\thooksPath = " + filepath.Dir(script) + "\n\tpager = " + script + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	t.Setenv("GIT_DIR", "/nonexistent") // inherited GIT_* must not leak in

	ctx := context.Background()
	files, err := ListFiles(ctx, repo)
	require.NoError(t, err)
	assert.Contains(t, files, "a.txt")
	_, err = InForce(ctx, repo)
	require.NoError(t, err)
	_, err = os.Stat(marker)
	assert.True(t, os.IsNotExist(err), "git executed the poisoned fsmonitor/pager")
}
