package research

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestChangedSince(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"a.txt": "a\n", "b.txt": "b\n"})
	out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	require.NoError(t, err)
	sha := strings.TrimSpace(string(out))

	got, err := ChangedSince(context.Background(), root, sha)
	require.NoError(t, err)
	assert.Empty(t, got)

	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte("changed\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "new.txt"), []byte("n\n"), 0o644))
	require.NoError(t, os.Remove(filepath.Join(root, "b.txt")))
	got, err = ChangedSince(context.Background(), root, sha)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a.txt", "b.txt", "new.txt"}, got)

	_, err = ChangedSince(context.Background(), root, "--output=x")
	assert.Error(t, err)
}

func TestRunDirtyTreeIsNotCached(t *testing.T) {
	spec := core.StrictDefaults().Research
	body := "FACTS:\n- a b c | s | [V]\nREAD:\n- src/a.php\nCOST: tokens=1 calls=1\n"
	rr := &roleRunner{calls: map[string]int{}, body: map[string]string{"code-scout": body, "test-scout": body}}
	dir := t.TempDir()
	dirty := Request{SHA: sha1, Question: "q", Goal: "g", Mode: core.ModeGuarded, Inv: Inv{Changed: []string{"unrelated.txt"}, Now: time.Now()}}
	_, err := Run(context.Background(), rr, dir, spec, dirty)
	require.NoError(t, err)

	clean := dirty
	clean.Inv.Changed = nil
	res, err := Run(context.Background(), rr, dir, spec, clean)
	require.NoError(t, err)
	assert.Equal(t, 0, res.CacheHits, "the dirty run wrote nothing")
	assert.Equal(t, 2, rr.calls["code-scout"])

	res, err = Run(context.Background(), rr, dir, spec, clean)
	require.NoError(t, err)
	assert.Equal(t, 2, res.CacheHits, "a clean run is cached")
}

func TestChangedSinceIgnoresRRState(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"a.txt": "a\n"})
	sha := strings.TrimSpace(testutil.Git(t, root, "rev-parse", "HEAD"))
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".rr/run"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".rr/run/t.research.md"), []byte("x"), 0o644))
	got, err := ChangedSince(context.Background(), root, sha)
	require.NoError(t, err)
	assert.Empty(t, got)
}
