package autonomy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// withProtected commits a file under .github/workflows (a protected path) to the test repo.
func withProtected(t *testing.T, e *env) {
	require.NoError(t, os.MkdirAll(filepath.Join(e.root, ".github/workflows"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(e.root, ".github/workflows/ci.yml"), []byte("on: push\n"), 0o644))
	testutil.Git(t, e.root, "add", "-A")
	testutil.Git(t, e.root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "ci")
}

func blockedReason(t *testing.T, e *env) string {
	evs, _ := e.jr.Events(context.Background(), "run1")
	for _, ev := range evs {
		if ev.Type == "task_blocked" {
			return string(ev.Data)
		}
	}
	return ""
}

func TestRenameOrDeleteOfProtectedPathIsBlocked(t *testing.T) {
	for name, act := range map[string]func(root string) error{
		"rename": func(root string) error {
			return os.Rename(filepath.Join(root, ".github/workflows/ci.yml"), filepath.Join(root, "ok.txt"))
		},
		"delete": func(root string) error { return os.Remove(filepath.Join(root, ".github/workflows/ci.yml")) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			withProtected(t, e)
			e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
				return done("ok"), act(e.root)
			}
			out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
			require.NoError(t, err)
			assert.Equal(t, "blocked", out[0].Status)
			assert.Contains(t, blockedReason(t, e), "protected path .github/workflows/ci.yml")
			assert.Empty(t, e.pushed)
		})
	}
}

func TestSymlinkedManifestDirIsNeverFollowed(t *testing.T) {
	e := newEnv(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "settings.json")
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		require.NoError(t, os.RemoveAll(filepath.Join(e.root, ".claude")))
		require.NoError(t, os.Symlink(outside, filepath.Join(e.root, ".claude")))
		require.NoError(t, os.WriteFile(victim, []byte("host file"), 0o644))
		return done("ok"), nil
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.Equal(t, "blocked", out[0].Status)
	assert.FileExists(t, victim, "the runner must not delete outside the checkout")
	assert.Equal(t, "host file", string(mustRead(t, victim)))
}

func TestRenderRefusesSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, ".claude")))
	err := safeWrite(root, []core.File{{Path: ".claude/settings.json", Content: []byte("x")}})
	assert.Error(t, err)
	assert.NoFileExists(t, filepath.Join(outside, "settings.json"))
	// a symlinked file itself
	root = t.TempDir()
	require.NoError(t, os.Symlink(filepath.Join(outside, "t"), filepath.Join(root, "f")))
	assert.Error(t, safeWrite(root, []core.File{{Path: "f", Content: []byte("x")}}))
	assert.NoError(t, safeWrite(t.TempDir(), []core.File{{Path: "a/b/c", Content: []byte("x")}}))
}

func TestDailyLimitSurvivesANewRunner(t *testing.T) {
	one := 1
	e1 := newEnv(t)
	e1.pol.Autonomy.Unattended.MaxTasksPerDay = &one
	_, err := e1.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)

	e2 := newEnv(t)
	e2.pol.Autonomy.Unattended.MaxTasksPerDay = &one
	e2.r.StateDir = e1.r.StateDir
	_, err = e2.r.Run(t.Context(), []Task{{ID: "t2", Brief: "x"}})
	assert.Equal(t, "BUDGET", e2.refusal(t, err).Code)
	assert.Zero(t, e2.worker.calls)
}

func TestStateDirInsideCheckoutIsRefused(t *testing.T) {
	e := newEnv(t)
	e.r.StateDir = filepath.Join(e.root, "sub", "state")
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Error(t, err)
	assert.Zero(t, e.worker.calls)

	e = newEnv(t) // a symlink out of the checkout into it does not help
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(e.root, link))
	e.r.StateDir = link
	_, err = e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Error(t, err)
}

func TestRescoreBlocksWhatTheDiffMakesRiskier(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		require.NoError(t, os.MkdirAll(filepath.Join(e.root, "migrations"), 0o755))
		return done("ok"), os.WriteFile(filepath.Join(e.root, "migrations/001.sql"), []byte("DROP TABLE users;\n"), 0o644)
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "tidy"}})
	require.NoError(t, err)
	assert.Equal(t, "blocked", out[0].Status)
	assert.Contains(t, blockedReason(t, e), "rescored to")
	assert.Empty(t, e.host.Opened)
}

func TestUnknownTokenUsageWithABudgetStopsTheRun(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		return core.WorkerReport{Status: core.StatusBlocked}, nil // no usage (codex, or a failed worker)
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}, {ID: "t2", Brief: "y"}})
	assert.Equal(t, "BUDGET", e.refusal(t, err).Code)
	assert.Equal(t, 1, e.worker.calls)

	e = newEnv(t) // no budget in the policy: unknown usage is fine
	e.pol.Models.Budgets = nil
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		return core.WorkerReport{Status: core.StatusBlocked}, nil
	}
	_, err = e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.NoError(t, err)
}

func agentJournal(t *testing.T, e *env, task string) {
	_, err := journal.New(e.root).Append(context.Background(), core.Event{Type: "task_started", Task: task, Actor: core.ActorAgent})
	require.NoError(t, err)
}

func TestAnchorRefusesSymlinkOversizeAndChecksAfterTheLastTask(t *testing.T) {
	t.Run("symlinked journal", func(t *testing.T) {
		e := newEnv(t)
		e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
			require.NoError(t, os.MkdirAll(filepath.Join(e.root, ".rr/run"), 0o755))
			require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(e.root, ".rr/run/t1.jsonl")))
			return done("ok"), nil
		}
		_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
		assert.Equal(t, "JOURNAL_TAMPERED", e.refusal(t, err).Code)
	})
	t.Run("oversize journal", func(t *testing.T) {
		e := newEnv(t)
		e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
			require.NoError(t, os.MkdirAll(filepath.Join(e.root, ".rr/run"), 0o755))
			f, err := os.Create(filepath.Join(e.root, ".rr/run/t1.jsonl"))
			require.NoError(t, err)
			require.NoError(t, f.Truncate(maxJournal+1))
			require.NoError(t, f.Close())
			return done("ok"), nil
		}
		_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
		assert.Equal(t, "JOURNAL_TAMPERED", e.refusal(t, err).Code)
	})
	t.Run("tampered after the last task", func(t *testing.T) {
		e := newEnv(t)
		e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
			agentJournal(t, e, "t1")
			return done("ok"), os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("n\n"), 0o644)
		}
		e.r.Push = func(context.Context, string, string) error {
			return os.Remove(filepath.Join(e.root, ".rr/run/t1.jsonl"))
		}
		_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
		assert.Equal(t, "JOURNAL_TAMPERED", e.refusal(t, err).Code, "no next wave, the final verify catches it")
	})
	t.Run("copies are namespaced by run id", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "journal-other-t9.jsonl"), []byte("x\n"), 0o600))
		assert.NoError(t, anchor{root: t.TempDir(), dir: dir, run: "mine"}.verify())
	})
}

func TestPRBodyFencesAgentText(t *testing.T) {
	evil := "done ``````\n@org/team @bob ping\n## injected\n" + strings.Repeat("é", 3000)
	b := prBody(Task{ID: "t1", Mode: core.ModeLight}, core.L2, core.WorkerReport{Status: core.StatusDone, Body: evil})
	assert.NotContains(t, b, "@bob", "mentions are neutralised")
	assert.Contains(t, b, "@\u200bbob")
	assert.Contains(t, b, "\n```````\n", "fence is longer than the longest backtick run (6)")
	assert.True(t, strings.Index(b, "- level: L2") < strings.Index(b, "```````"), "runner fields come first")
	assert.True(t, strings.HasPrefix(b, "## rr task t1"))
	assert.True(t, utf8Valid(b))
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

func TestNestedRepoIsCleanedAndRerunSameTaskWorks(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(_ context.Context, n int, _ core.WorkerSpec) (core.WorkerReport, error) {
		if n == 1 {
			nested := filepath.Join(e.root, "evil")
			require.NoError(t, os.MkdirAll(nested, 0o755))
			testutil.Git(t, nested, "init", "-q")
			return core.WorkerReport{Status: core.StatusNeedsContext, Tokens: 5}, nil
		}
		return done("ok"), os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("again\n"), 0o644)
	}
	out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	require.NoError(t, err)
	assert.Equal(t, "blocked", out[0].Status)
	assert.NoDirExists(t, filepath.Join(e.root, "evil"), "nested repository removed")

	out, err = e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}}) // same id, rr/t1 already exists
	require.NoError(t, err)
	assert.Equal(t, "pr", out[0].Status)
}

func TestGitDirMustBeARealDirectory(t *testing.T) {
	e := newEnv(t)
	require.NoError(t, os.RemoveAll(filepath.Join(e.root, ".git")))
	require.NoError(t, os.WriteFile(filepath.Join(e.root, ".git"), []byte("gitdir: /elsewhere"), 0o644))
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Error(t, err)
	assert.Zero(t, e.worker.calls)
}

func TestHaltBeforePushStopsThePush(t *testing.T) {
	e := newEnv(t)
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		e.host.set("main:.rr/HALT", []byte("stop")) // appears after the poller's last look
		return done("ok"), os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("n\n"), 0o644)
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "HALT", e.refusal(t, err).Code)
	assert.Empty(t, e.pushed)
	assert.Empty(t, e.host.Opened)
}

func TestWallDeadlineIsBudgetButCallerCancelIsNot(t *testing.T) {
	e := newEnv(t)
	e.r.WallUnit = time.Millisecond
	e.worker.fn = func(ctx context.Context, _ int, _ core.WorkerSpec) (core.WorkerReport, error) {
		<-ctx.Done()
		return core.WorkerReport{Status: core.StatusBlocked}, ctx.Err()
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "BUDGET", e.refusal(t, err).Code)
	assert.Contains(t, e.jr.Types("run1"), "run_budget_exceeded")

	e = newEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	e.worker.fn = func(wctx context.Context, _ int, _ core.WorkerSpec) (core.WorkerReport, error) {
		cancel()
		<-wctx.Done()
		return core.WorkerReport{Status: core.StatusBlocked}, wctx.Err()
	}
	_, err = e.r.Run(ctx, []Task{{ID: "t1", Brief: "x"}})
	assert.True(t, errors.Is(err, context.Canceled), "%v", err)
	var ref *core.Refusal
	assert.False(t, errors.As(err, &ref), "a cancelled caller is not a wall budget")
}

// Opus round 3: AlwaysProtected paths (agent configs, skills, MCP) block like protected_paths.
func TestAlwaysProtectedChangeIsBlocked(t *testing.T) {
	for _, p := range []string{".mcp.json", ".claude/commands/deploy.md", ".agents/skills/x/SKILL.md"} {
		t.Run(p, func(t *testing.T) {
			e := newEnv(t)
			e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
				require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(e.root, p)), 0o755))
				return done("ok"), os.WriteFile(filepath.Join(e.root, p), []byte("x"), 0o644)
			}
			out, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
			require.NoError(t, err)
			assert.Equal(t, "blocked", out[0].Status)
			assert.Contains(t, blockedReason(t, e), "protected path "+p)
			assert.Empty(t, e.pushed)
		})
	}
}

// Opus round 3: an over-budget task leaves no agent tree, no L2 manifests and no ignored files.
func TestBudgetDiscardsAgentTree(t *testing.T) {
	e := newEnv(t)
	e.pol.Models.Budgets = map[core.Mode]core.TokenCount{core.ModeLight: 50}
	base := strings.TrimSpace(testutil.Git(t, e.root, "rev-parse", "HEAD"))
	e.worker.fn = func(context.Context, int, core.WorkerSpec) (core.WorkerReport, error) {
		require.NoError(t, os.MkdirAll(filepath.Join(e.root, "node_modules/.bin"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(e.root, "node_modules/.bin/jest"), []byte("x"), 0o755))
		return done("ok"), os.WriteFile(filepath.Join(e.root, "a.txt"), []byte("agent\n"), 0o644)
	}
	_, err := e.r.Run(t.Context(), []Task{{ID: "t1", Brief: "x"}})
	assert.Equal(t, "BUDGET", e.refusal(t, err).Code)
	assert.Equal(t, base, strings.TrimSpace(testutil.Git(t, e.root, "rev-parse", "HEAD")))
	assert.Empty(t, strings.TrimSpace(testutil.Git(t, e.root, "status", "--porcelain", "--ignored", "--", ".", ":!.rr")))
}
