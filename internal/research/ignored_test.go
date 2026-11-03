package research

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// A scout READ of a git-ignored file that later changes invalidates the cache entry,
// although ChangedSince (git) never lists it.
func TestRunIgnoredFileInvalidates(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "local.cfg"), []byte("v1"), 0o600))
	spec := core.StrictDefaults().Research
	body := "FACTS:\n- a b c | s | [V]\nREAD:\n- local.cfg:3\nCOST: tokens=1 calls=1\n"
	rr := &roleRunner{calls: map[string]int{}, body: map[string]string{"code-scout": body, "test-scout": body}}
	dir := t.TempDir()
	req := Request{SHA: sha1, Question: "q", Goal: "g", Mode: core.ModeGuarded, Inv: Inv{Root: root, Now: time.Now()}}

	_, err := Run(context.Background(), rr, dir, spec, req)
	require.NoError(t, err)
	res, err := Run(context.Background(), rr, dir, spec, req)
	require.NoError(t, err)
	assert.Equal(t, 2, res.CacheHits)

	require.NoError(t, os.WriteFile(filepath.Join(root, "local.cfg"), []byte("v2"), 0o600))
	res, err = Run(context.Background(), rr, dir, spec, req)
	require.NoError(t, err)
	assert.Equal(t, 0, res.CacheHits)
	assert.Equal(t, 2, rr.calls["code-scout"])

	require.NoError(t, os.Remove(filepath.Join(root, "local.cfg"))) // vanished = changed
	res, err = Run(context.Background(), rr, dir, spec, req)
	require.NoError(t, err)
	assert.Equal(t, 0, res.CacheHits)
}

func TestHashReadSkipsEscapesAndDirs(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "d"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o600))
	got := HashRead(root, []string{"f", "d", "../etc/passwd", "/etc/passwd", "missing"})
	assert.Len(t, got, 1)
	assert.Contains(t, got, "f")
	// entries with hashes cannot be verified without a root: invalid
	e := Entry{Role: "code", Read: []string{"f"}, Files: got}
	assert.False(t, Valid(e, Inv{}))
	assert.True(t, Valid(e, Inv{Root: root}))
}
