package verify

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestUncoveredIsAHardFloor(t *testing.T) {
	full, reason := FullRunRequired(core.VerifySpec{FullRunWhen: []string{}}, []string{"x"}, []string{"x"}, core.ModeLight, false)
	assert.True(t, full)
	assert.Contains(t, reason, "uncovered_file")
}

func TestTreeChangedDuringRun(t *testing.T) {
	j := &fakes.Journal{}
	s := &stub{name: "go", tests: []string{"./a"}, pass: true}
	in := orchInput(j, s)
	n := 0
	in.Tree = func(context.Context) (string, error) { n++; return []string{"T1", "T2"}[n-1], nil }
	rep, err := Run(context.Background(), in)
	require.NoError(t, err)
	assert.False(t, rep.Passed)
	ev, _ := j.Events(context.Background(), "t1")
	assert.Contains(t, string(ev[0].Data), `"passed":false`)
}

func TestChangedFilesHardening(t *testing.T) {
	ctx := context.Background()
	root := testutil.GitRepo(t, map[string]string{"in/a.txt": "a content", "b.txt": "b", "c.txt": "c"})

	require.NoError(t, os.MkdirAll(filepath.Join(root, "out"), 0o755))
	testutil.Git(t, root, "mv", "in/a.txt", "out/a.txt")
	files, err := ChangedFiles(ctx, root, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"in/a.txt", "out/a.txt"}, files, "a rename out of scope lists both paths")
	testutil.Git(t, root, "mv", "out/a.txt", "in/a.txt")

	testutil.Git(t, root, "update-index", "--assume-unchanged", "b.txt")
	testutil.Git(t, root, "update-index", "--skip-worktree", "c.txt")
	write(t, root, map[string]string{"b.txt": "evil", "c.txt": "evil", ".rr/run/x.jsonl": "{}"})
	files, err = ChangedFiles(ctx, root, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"b.txt", "c.txt"}, files, "hidden-from-vcs edits count as changed; .rr/ is excluded")
}

func TestTreeFingerprintSensitivity(t *testing.T) {
	ctx := context.Background()
	root := testutil.GitRepo(t, map[string]string{"a.txt": "a", ".gitignore": "ign/\n"})
	fp := func() string {
		s, err := TreeFingerprint(ctx, root)
		require.NoError(t, err)
		return s
	}
	base := fp()
	assert.Equal(t, base, fp(), "stable")

	write(t, root, map[string]string{".rr/run/x": "noise"})
	assert.Equal(t, base, fp(), ".rr/ is ignored")

	write(t, root, map[string]string{"ign/cache": "1"})
	withIgnored := fp()
	assert.NotEqual(t, base, withIgnored, "ignored files count")
	write(t, root, map[string]string{"ign/cache": "2"})
	assert.NotEqual(t, withIgnored, fp())

	write(t, root, map[string]string{"a.txt": ""})
	empty := fp()
	require.NoError(t, os.Remove(filepath.Join(root, "a.txt")))
	assert.NotEqual(t, empty, fp(), "deleted differs from empty")

	if os.Geteuid() != 0 {
		write(t, root, map[string]string{"locked.txt": "x"})
		require.NoError(t, os.Chmod(filepath.Join(root, "locked.txt"), 0))
		_, err := TreeFingerprint(ctx, root)
		assert.Error(t, err, "unreadable file must not be silent")
	}
}
