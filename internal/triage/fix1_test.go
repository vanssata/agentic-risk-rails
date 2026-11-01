package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644))
}

// scoreLoaded runs the real loader, then Score, for one file.
func scoreLoaded(t *testing.T, root, f string) core.Weight {
	refs, content, unreadable := Load(root, []string{f}, nil, nil)
	return Score(sq1Policy(), Input{Files: []string{f}, Refs: refs, Content: content, Unreadable: unreadable})
}

func TestUnreadableErrsUpward(t *testing.T) {
	root := t.TempDir()
	write(t, root, "migrations/nul.php", "\x00\x00 DROP TABLE users")
	write(t, root, "migrations/big.php", strings.Repeat(" ", 1<<20)+"DROP TABLE users")
	write(t, root, "migrations/ok.php", "plain")
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(root, "migrations/d.php")))
	for _, f := range []string{"migrations/nul.php", "migrations/big.php", "migrations/d.php"} {
		w := scoreLoaded(t, root, f)
		assert.Equal(t, 2, w.Axes[rv], f)
		assert.GreaterOrEqual(t, w.Axes[bh], 1, f)
	}
	assert.Equal(t, 1, scoreLoaded(t, root, "migrations/ok.php").Axes[rv])
}

func TestLoadConfinement(t *testing.T) {
	root := t.TempDir()
	write(t, root, "../outside.txt", "x")
	for _, f := range []string{"../outside.txt", "/etc/passwd", "a/../../outside.txt"} {
		_, _, unreadable := Load(root, []string{f}, nil, nil)
		assert.True(t, unreadable[f], f)
	}
	_, content, _ := Load(root, []string{"/etc/passwd"}, nil, nil)
	assert.Empty(t, content["/etc/passwd"], "never read")
}

func TestDeletedIsNotNew(t *testing.T) {
	pol := sq1Policy()
	in := Input{Files: []string{"migrations/V1.php"}, Deleted: map[string]bool{"migrations/V1.php": true}}
	w := Score(pol, in)
	assert.GreaterOrEqual(t, w.Axes[bh], 1)
	assert.Equal(t, 1, w.Axes[rv], "by its globs")
	in.Deleted = nil
	assert.Equal(t, 0, Score(pol, in).Axes[bh], "same file without the deleted flag is new")
}

func TestRescoreAppliesPolicyFileWeight(t *testing.T) {
	pol := sq1Policy()
	pol.Risk.Rescore.Axes = []core.Axis{core.AxisReversibility}
	prev := Score(pol, Input{Files: []string{"a.txt"}, Declared: decl(bh, 0, dm, 0, nv, 0)})
	got := Rescore(pol, prev, Input{Files: []string{"a.txt", "riskrails.yaml"}})
	assert.Equal(t, 2, got.Axes[dm])
	assert.Equal(t, core.ModeFull, got.Mode)
}

func TestContentCaseInsensitive(t *testing.T) {
	in := Input{Files: []string{"config/db.php"}, Content: map[string]string{"config/db.php": "drop table x"}}
	assert.Equal(t, 2, Score(sq1Policy(), in).Axes[rv])
}

func TestCoverageIdentIsAWord(t *testing.T) {
	pol := sq1Policy()
	in := Input{Files: []string{"src/User.php"}, Tree: []string{"tests/SuperUserTest.php"}}
	assert.Equal(t, 2, Score(pol, in).Axes[cv])
	in.Tree = []string{"tests/UserTest.php"}
	assert.Equal(t, 0, Score(pol, in).Axes[cv])
}

func TestTestFixtureExemptFromContentScan(t *testing.T) {
	in := Input{Files: []string{"tests/migrations/schema.sql"}, Refs: map[string]int{"tests/migrations/schema.sql": 0},
		Content: map[string]string{"tests/migrations/schema.sql": "DROP TABLE t;"}}
	w := Score(sq1Policy(), in)
	assert.Equal(t, 1, w.Axes[rv], "needs_step by path, but the content scan skips test files")
	in.Files, in.Refs = []string{"src/migrations/schema.sql"}, map[string]int{"src/migrations/schema.sql": 0}
	in.Content = map[string]string{"src/migrations/schema.sql": "DROP TABLE t;"}
	assert.Equal(t, 2, Score(sq1Policy(), in).Axes[rv])
}
