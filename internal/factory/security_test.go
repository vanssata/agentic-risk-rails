package factory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/plan"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func runOne(t *testing.T, f *Factory) Result {
	t.Helper()
	res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a")}})
	require.NoError(t, err)
	require.Len(t, res, 1)
	return res[0]
}

func TestWorktreeGitFileIsNeverTrusted(t *testing.T) {
	// The planted gitdir is a clone of Root whose index is read-tree'd from HEAD
	// for the worktree, so a scope check that trusted it would pass; its
	// attributes and config run `touch marker` as clean filter on every file.
	marker := filepath.Join(t.TempDir(), "pwned")
	f, _ := newFactory(t, nil, reviews(pass1))
	evilDir := t.TempDir()
	testutil.Git(t, evilDir, "clone", "-q", "--no-checkout", f.Root, ".")
	evil := filepath.Join(evilDir, ".git")
	require.NoError(t, os.WriteFile(filepath.Join(evil, "info", "attributes"), []byte("* filter=pwn\n"), 0o644))
	cfg, err := os.OpenFile(filepath.Join(evil, "config"), os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = cfg.WriteString("[filter \"pwn\"]\n\tclean = touch " + marker + "; cat\n")
	require.NoError(t, err)
	require.NoError(t, cfg.Close())
	f.Implementer = runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
		_ = os.WriteFile(filepath.Join(s.Worktree, "a.txt"), []byte("x\n"), 0o644)
		testutil.Git(t, s.Worktree, "--git-dir="+evil, "--work-tree="+s.Worktree, "read-tree", "HEAD")
		_ = os.WriteFile(filepath.Join(s.Worktree, ".git"), []byte("gitdir: "+evil+"\n"), 0o644)
		return rep(core.StatusDone, "ok")
	})
	res := runOne(t, f)
	assert.NoFileExists(t, marker, "the filter of the planted gitdir must not run on the host")
	assert.True(t, res.OK(), res.Blocked)
	assert.NoDirExists(t, filepath.Join(f.WorkDir, "a"), "worktree removed even with a rewritten .git")
}

func TestDeletedDotGitDoesNotWalkUp(t *testing.T) {
	impl := runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
		_ = os.WriteFile(filepath.Join(s.Worktree, "a.txt"), []byte("x\n"), 0o644)
		_ = os.Remove(filepath.Join(s.Worktree, ".git"))
		return rep(core.StatusDone, "ok")
	})
	f, _ := newFactory(t, impl, reviews(pass1))
	f.WorkDir = filepath.Join(f.Root, ".wt") // a parent repo exists above the worktree
	res := runOne(t, f)
	require.True(t, res.OK(), res.Blocked)
	assert.Equal(t, "a.txt", strings.TrimSpace(testutil.Git(t, f.Root, "show", "--name-only", "--format=", "HEAD")))
}

func TestInTreeFilterAttributeIsRefused(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	f, j := newFactory(t, &writer{}, reviews(pass1))
	root := testutil.GitRepo(t, map[string]string{".gitattributes": "*.txt filter=pwn\n", "README.md": "x\n"})
	testutil.Git(t, root, "config", "filter.pwn.clean", "touch "+marker+"; cat")
	f.Root = root
	res := runOne(t, f)
	assert.NoFileExists(t, marker)
	assert.False(t, res.OK())
	assert.Contains(t, res.Blocked, "attribute")
	assert.Contains(t, j.Types("t1"), "scope_violation")
}

func TestLiteralPathspecs(t *testing.T) {
	// a step file named like a pathspec magic can not be written by the plan,
	// and git is told to treat what is left literally.
	_, err := plan.Waves(plan.Plan{Steps: []plan.Step{{ID: "a", Files: []string{":(top)x"}}}})
	assert.Error(t, err)
}

func TestSymlinksAreBlocked(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		setup func(wt string)
	}{
		{"file is a symlink", "a.txt", func(wt string) { _ = os.Symlink("/etc/hostname", filepath.Join(wt, "a.txt")) }},
		{"parent dir is a symlink", "d/a.txt", func(wt string) {
			other := filepath.Join(wt, "..", "elsewhere")
			_ = os.MkdirAll(other, 0o755)
			_ = os.Symlink(other, filepath.Join(wt, "d"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			impl := runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
				tc.setup(s.Worktree)
				return rep(core.StatusDone, "ok")
			})
			f, j := newFactory(t, impl, reviews(pass1))
			res, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{{ID: "a", Files: []string{tc.file}}}})
			require.NoError(t, err)
			assert.False(t, res[0].OK())
			assert.Contains(t, res[0].Blocked, "symlink")
			assert.Contains(t, j.Types("t1"), "scope_violation")
		})
	}
}

func TestFixerCases(t *testing.T) {
	tests := []struct {
		name      string
		fixer     func(wt string) core.WorkerReport
		wantBlock string
		audit     bool
	}{
		{"fixer BLOCKED blocks the step, no hard error", func(string) core.WorkerReport { return rep(core.StatusBlocked, "cannot") }, "fixer BLOCKED", false},
		{"fixer leaves the scope", func(wt string) core.WorkerReport {
			_ = os.WriteFile(filepath.Join(wt, "other.txt"), []byte("x"), 0o644)
			return rep(core.StatusDone, "ok")
		}, "scope", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			impl := runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
				if s.Role == "fixer" {
					return tc.fixer(s.Worktree)
				}
				_ = os.WriteFile(filepath.Join(s.Worktree, "a.txt"), []byte("x"), 0o644)
				return rep(core.StatusDone, "ok")
			})
			f, j := newFactory(t, impl, reviews(fail1))
			res := runOne(t, f)
			assert.False(t, res.OK())
			assert.Contains(t, res.Blocked, tc.wantBlock)
			assert.Equal(t, tc.audit, strings.Contains(strings.Join(j.Types("t1"), ","), "scope_violation"))
		})
	}
}

func TestPass(t *testing.T) {
	tests := []struct {
		name string
		rep  core.WorkerReport
		want bool
	}{
		{"pass", rep("DONE", "x\nVERDICT: PASS"), true},
		{"pass with concerns status", rep("DONE_WITH_CONCERNS", "VERDICT: PASS"), true},
		{"case and spacing", rep("DONE", "  verdict:   pass  "), true},
		{"no verdict", rep("DONE", "all good"), false},
		{"fail", rep("DONE", "VERDICT: FAIL"), false},
		{"last verdict wins: fail last", rep("DONE", "VERDICT: PASS\nVERDICT: FAIL"), false},
		{"any FAIL fails even if last is PASS", rep("DONE", "VERDICT: FAIL\nVERDICT: PASS"), false},
		{"quoted verdict inside prose is not a verdict line", rep("DONE", "the template says VERDICT: PASS|FAIL"), false},
		{"BLOCKED status fails", rep("BLOCKED", "VERDICT: PASS"), false},
		{"NEEDS_CONTEXT status fails", rep("NEEDS_CONTEXT", "VERDICT: PASS"), false},
		{"empty status fails", rep("", "VERDICT: PASS"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, pass(tc.rep)) })
	}
}

func TestIntegrationIsJournalled(t *testing.T) {
	f, j := newFactory(t, &writer{}, reviews(pass1))
	res := runOne(t, f)
	require.True(t, res.OK())
	types := j.Types("t1")
	assert.Equal(t, "step_started", types[0])
	assert.Equal(t, "step_integrated", types[len(types)-1])
	var data string
	for _, e := range j.ByTask["t1"] {
		if e.Type == "step_integrated" {
			data = string(e.Data)
		}
	}
	assert.Contains(t, data, res.Commit)
}

func TestClaudeRunnerReadOnlyAndTimeout(t *testing.T) {
	wt := t.TempDir()
	bin := testutil.FakeBin(t, "claude", `echo "$@" > args.txt
printf '%s\n' '{"result":"VERDICT: PASS\nSTATUS: DONE"}'`)
	r := ClaudeRunner{Bin: bin, PermissionMode: "acceptEdits", Models: map[core.Tier]string{core.TierBalanced: "sonnet"}}
	got, err := r.ReadOnly().Run(context.Background(), core.WorkerSpec{Tier: core.TierBalanced, Worktree: wt})
	require.NoError(t, err)
	assert.Equal(t, core.StatusDone, got.Status)
	args, _ := os.ReadFile(filepath.Join(wt, "args.txt"))
	for _, want := range []string{"--permission-mode plan", "--tools Read,Grep,Glob", "--disallowedTools Edit,Write,MultiEdit,NotebookEdit,Bash", "--setting-sources user", "--strict-mcp-config"} {
		assert.Contains(t, string(args), want)
	}
	_, _ = r.Run(context.Background(), core.WorkerSpec{Tier: core.TierBalanced, Worktree: wt})
	args, _ = os.ReadFile(filepath.Join(wt, "args.txt"))
	assert.NotContains(t, string(args), "--tools", "the plain runner is not restricted")

	slow := testutil.FakeBin(t, "claude", "exec sleep 10")
	start := time.Now()
	r = ClaudeRunner{Bin: slow, Timeout: 200 * time.Millisecond, Models: map[core.Tier]string{core.TierBalanced: "sonnet"}}
	got, err = r.Run(context.Background(), core.WorkerSpec{Tier: core.TierBalanced, Worktree: wt})
	require.NoError(t, err)
	assert.Equal(t, core.StatusBlocked, got.Status)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func alive(pid string) bool {
	b, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	return s[strings.LastIndex(s, ")")+2] != 'Z'
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	wt := t.TempDir()
	bin := testutil.FakeBin(t, "claude", "sleep 30 &\necho $! > pid\nwait")
	r := ClaudeRunner{Bin: bin, Timeout: 300 * time.Millisecond, Models: map[core.Tier]string{core.TierBalanced: "sonnet"}}
	got, err := r.Run(context.Background(), core.WorkerSpec{Tier: core.TierBalanced, Worktree: wt})
	require.NoError(t, err)
	assert.Equal(t, core.StatusBlocked, got.Status)
	pid, err := os.ReadFile(filepath.Join(wt, "pid"))
	require.NoError(t, err)
	assert.Eventually(t, func() bool { return !alive(strings.TrimSpace(string(pid))) }, 3*time.Second, 50*time.Millisecond, "the background child must die with the group")
}

func TestReviewerCannotChangeWhatIsCommitted(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(wt string)
		want   string
	}{
		{"content changed", func(wt string) { _ = os.WriteFile(filepath.Join(wt, "a.txt"), []byte("changed\n"), 0o644) }, "changed after review"},
		{"became a symlink", func(wt string) {
			_ = os.Remove(filepath.Join(wt, "a.txt"))
			_ = os.Symlink("/etc/passwd", filepath.Join(wt, "a.txt"))
		}, "symlink"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, j := newFactory(t, &writer{}, nil)
			f.Reviewer = ro{runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
				tc.mutate(s.Worktree)
				return rep(core.StatusDone, pass1)
			})}
			res := runOne(t, f)
			assert.False(t, res.OK())
			assert.Contains(t, res.Blocked, tc.want)
			assert.Contains(t, j.Types("t1"), "scope_violation")
			assert.NoFileExists(t, filepath.Join(f.Root, "a.txt"))
		})
	}
}

func TestScopeRejects(t *testing.T) {
	tests := []struct {
		name  string
		repo  map[string]string
		write func(t *testing.T, wt string)
		want  string
	}{
		{"nested repository", nil, func(t *testing.T, wt string) {
			d := filepath.Join(wt, "a.txt")
			require.NoError(t, os.MkdirAll(d, 0o755))
			testutil.Git(t, d, "init", "-q")
			require.NoError(t, os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644))
			testutil.Git(t, d, "add", "f")
			testutil.Git(t, d, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-q", "-m", "x")
		}, "directory"},
		{"ignored .claude settings", map[string]string{".gitignore": ".claude/\n"}, func(t *testing.T, wt string) {
			require.NoError(t, os.MkdirAll(filepath.Join(wt, ".claude"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(wt, ".claude", "settings.local.json"), []byte("{}"), 0o644))
		}, "configures the agent"},
		{"ignored .mcp.json", map[string]string{".gitignore": ".mcp.json\n"}, func(t *testing.T, wt string) {
			require.NoError(t, os.WriteFile(filepath.Join(wt, ".mcp.json"), []byte("{}"), 0o644))
		}, "configures the agent"},
		{"ignored nested CLAUDE.md", map[string]string{".gitignore": "CLAUDE.md\n"}, func(t *testing.T, wt string) {
			require.NoError(t, os.MkdirAll(filepath.Join(wt, "sub"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(wt, "sub", "CLAUDE.md"), []byte("x"), 0o644))
		}, "configures the agent"},
		{"custom merge driver", map[string]string{".gitattributes": "*.txt merge=evil\n"}, func(t *testing.T, wt string) {
			require.NoError(t, os.WriteFile(filepath.Join(wt, "a.txt"), []byte("x"), 0o644))
		}, "attribute"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newFactory(t, runnerFunc(func(s core.WorkerSpec) core.WorkerReport {
				if s.Role == "implementer" {
					tc.write(t, s.Worktree)
				}
				return rep(core.StatusDone, "ok")
			}), reviews(pass1))
			if tc.repo != nil {
				tc.repo["README.md"] = "x\n"
				f.Root = testutil.GitRepo(t, tc.repo)
			}
			res := runOne(t, f)
			assert.False(t, res.OK())
			assert.Contains(t, res.Blocked, tc.want)
		})
	}
}

func TestIDValidation(t *testing.T) {
	for _, id := range []string{"-rf", "a/b", "..", ".", "a b", "", "x\n"} {
		assert.False(t, plan.ValidID(id), id)
	}
	for _, id := range []string{"a", "step-1", "s_2.x", "A9"} {
		assert.True(t, plan.ValidID(id), id)
	}
	assert.Error(t, plan.Check(plan.Plan{Steps: []plan.Step{{ID: "-x", Files: []string{"a"}}}}))
	f, _ := newFactory(t, &writer{}, reviews(pass1))
	f.Task = "--bad"
	_, err := f.RunWaves(context.Background(), plan.Plan{Steps: []plan.Step{step("a")}})
	assert.Error(t, err)
}

func TestStatusOfLastLineOnly(t *testing.T) {
	tests := []struct {
		body string
		want core.WorkerStatus
	}{
		{"work\nSTATUS: DONE", core.StatusDone},
		{"work\nSTATUS: DONE\n\n", core.StatusDone},
		{"STATUS: DONE\nbut then I failed", core.StatusBlocked},
		{"STATUS: DONE\nSTATUS: BLOCKED", core.StatusBlocked},
		{"STATUS: NEEDS_CONTEXT", core.StatusNeedsContext},
		{"STATUS: DONE_WITH_CONCERNS", core.StatusDoneWithConcerns},
		{"STATUS: NOPE", core.StatusBlocked},
		{"", core.StatusBlocked},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, statusOf(tc.body), tc.body)
	}
}
