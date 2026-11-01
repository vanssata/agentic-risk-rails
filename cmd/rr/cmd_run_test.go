package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

var (
	askWord  = regexp.MustCompile(`(?i)\bask\b`)
	emptyAsk = regexp.MustCompile(`"ask":\s*(\[\s*\]|null)`) // an empty list is no ask
)

// At L≥2 no registered generator may leave an `ask` in a manifest (DES §8.2).
func TestGeneratorsCompileAskToDenyAtL2(t *testing.T) {
	restore := policy.SetCeilingPaths(filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "none"))
	defer restore()
	repo := testutil.CopyFixture(t, "php-symfony")
	in, err := syncInput(context.Background(), repo)
	require.NoError(t, err)
	require.NotEmpty(t, rrsync.Generators())
	count := func(l core.Level) (n int) {
		in.Level = l
		files, err := rrsync.Render(context.Background(), in, rrsync.Generators())
		require.NoError(t, err)
		for _, f := range files {
			if askWord.Match(emptyAsk.ReplaceAll(f.Content, nil)) {
				n++
				if l >= core.L2 {
					t.Errorf("%s still contains ask at %s", f.Path, l)
				}
			}
		}
		return n
	}
	assert.Positive(t, count(core.L1), "control: the fixture's ask entries show up below L2")
	assert.Zero(t, count(core.L2))
	assert.Zero(t, count(core.L4))
}

func TestRunFailsClosedWithoutHosting(t *testing.T) {
	q := filepath.Join(t.TempDir(), "q.yaml")
	require.NoError(t, os.WriteFile(q, []byte("- {id: t1, brief: do it}\n"), 0o644))
	_, err := runRR("run", "--queue", q, "--image", "img", "--root", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to run")
}

func TestRunRejectsLevelBelowL2AndBadQueue(t *testing.T) {
	q := filepath.Join(t.TempDir(), "q.yaml")
	require.NoError(t, os.WriteFile(q, []byte("- {id: t1, brief: x}\n"), 0o644))
	_, err := runRR("run", "--queue", q, "--image", "img", "--level", "L9")
	assert.Error(t, err)
	require.NoError(t, os.WriteFile(q, []byte("- {id: t1, brif: typo}\n"), 0o644))
	_, err = runRR("run", "--queue", q, "--image", "img")
	assert.Error(t, err, "unknown queue field")
}

func TestDefaultStateDirIsUnderXDGState(t *testing.T) {
	x := t.TempDir()
	t.Setenv("XDG_STATE_HOME", x)
	a, err := defaultStateDir("/repo/a")
	require.NoError(t, err)
	b, _ := defaultStateDir("/repo/b")
	assert.Equal(t, filepath.Join(x, "riskrails"), filepath.Dir(a))
	assert.NotEqual(t, a, b, "one state dir per checkout")
}

func TestRunEnforcementProbePrintsALevel(t *testing.T) {
	out, err := runRR("run", "enforcement", "--runtime", "claude")
	require.NoError(t, err)
	assert.Contains(t, []string{"sandbox", "hook_only", "ci_only"}, strings.TrimSpace(out))
	_, err = runRR("run", "enforcement", "--runtime", "nope")
	assert.Error(t, err)
}
