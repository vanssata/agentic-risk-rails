package autonomy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestIgnoredFilesDoNotSurviveIntoTheNextTask(t *testing.T) {
	for _, first := range []core.WorkerStatus{core.StatusNeedsContext, core.StatusDone} {
		t.Run(string(first), func(t *testing.T) {
			e := newEnv(t)
			require.NoError(t, os.WriteFile(filepath.Join(e.root, ".gitignore"), []byte(".rr/\nnode_modules/\n.env\n"), 0o644))
			testutil.Git(t, e.root, "add", "-A")
			testutil.Git(t, e.root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "ignore")
			e.syncTip(t)
			var leaked []string
			e.worker.fn = func(_ context.Context, n int, _ core.WorkerSpec) (core.WorkerReport, error) {
				if n == 1 {
					require.NoError(t, os.MkdirAll(filepath.Join(e.root, "node_modules/.bin"), 0o755))
					require.NoError(t, os.WriteFile(filepath.Join(e.root, "node_modules/.bin/x"), []byte("x"), 0o755))
					require.NoError(t, os.WriteFile(filepath.Join(e.root, ".env"), []byte("S=1"), 0o644))
					require.NoError(t, os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("one\n"), 0o644))
					return core.WorkerReport{Status: first, Tokens: 5}, nil
				}
				for _, p := range []string{"node_modules", ".env"} {
					if _, err := os.Lstat(filepath.Join(e.root, p)); err == nil {
						leaked = append(leaked, p)
					}
				}
				return done("ok"), nil
			}
			_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}, {ID: "t2", Brief: "y"}})
			require.NoError(t, err)
			assert.Empty(t, leaked)
		})
	}
}

func TestSymlinkGitlinkAndTypeChangeInDiffAreBlocked(t *testing.T) {
	cases := map[string]func(root string){
		"new symlink": func(root string) { require.NoError(t, os.Symlink("a.txt", filepath.Join(root, "link"))) },
		"type change": func(root string) {
			require.NoError(t, os.Remove(filepath.Join(root, "a.txt")))
			require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(root, "a.txt")))
		},
		"gitlink": func(root string) {
			nested := filepath.Join(root, "sub")
			require.NoError(t, os.MkdirAll(nested, 0o755))
			testutil.Git(t, nested, "init", "-q")
			require.NoError(t, os.WriteFile(filepath.Join(nested, "f"), []byte("f"), 0o644))
			testutil.Git(t, nested, "add", "-A")
			testutil.Git(t, nested, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "n")
		},
	}
	for name, act := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
				act(e.root)
				return done("ok"), nil
			}
			out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
			require.NoError(t, err)
			assert.Equal(t, "blocked", out[0].Status)
			assert.Contains(t, blockedReason(t, e), "symlink/gitlink in diff")
			assert.Empty(t, e.host.Pushed)
		})
	}
}

func TestFailedDockerRunRemovesTheContainer(t *testing.T) {
	root := repo(t)
	log := filepath.Join(t.TempDir(), "calls")
	testutil.FakeBin(t, "docker", `echo "$@" >> `+log+`
if [ "$1" = run ]; then exit 1; fi`)
	d := DockerRunner{Image: testImage, Runtime: "claude", Root: root, Network: "n", ProxyURL: "http://p:3128", PolicyFile: policyFile(t), Models: map[core.Tier]string{core.TierFast: "haiku"}}
	rep, err := d.Run(t.Context(), core.WorkerSpec{Tier: core.TierFast})
	require.NoError(t, err)
	assert.Equal(t, core.StatusBlocked, rep.Status)
	b, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	require.Len(t, lines, 2, string(b))
	name := strings.Fields(lines[0])[6] // run --rm --init --pull never --name <name>
	assert.Equal(t, "rm -f "+name, lines[1])
}

func TestTreeAtKeepsNonASCIINames(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"ünï/тест file.php": "x", "a.txt": "a"})
	r := &Runner{Root: root}
	tree, err := r.treeAt(t.Context(), "HEAD")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ünï/тест file.php", "a.txt"}, tree)
}

func TestFirstLineCutsOnARuneBoundaryAndPRBodyIsAdvisory(t *testing.T) {
	l := firstLine(strings.Repeat("é", 100))
	assert.True(t, strings.ToValidUTF8(l, "") == l)
	assert.LessOrEqual(t, len(l), 72)
	b := prBody(Task{ID: "t1"}, core.L2, core.WorkerReport{Status: core.StatusDone}, core.Weight{}, nil)
	assert.Contains(t, b, "reported by the agent: advisory")
}
