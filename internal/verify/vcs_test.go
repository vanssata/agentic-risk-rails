package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// startedTask does what the flow does at task start: baseline manifest file plus
// the task_started data {scope, base_sha, baseline}.
func startedTask(t *testing.T, root, task string, scope []string) []core.Event {
	t.Helper()
	ctx := context.Background()
	manifest, sha, err := Baseline(ctx, root)
	require.NoError(t, err)
	base, err := HeadSHA(ctx, root)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(journal.RunDir(root), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(journal.RunDir(root), task+".baseline.json"), manifest, 0o644))
	data, err := json.Marshal(map[string]any{"scope": scope, "base_sha": base, "baseline": sha, "mode": "guarded"})
	require.NoError(t, err)
	return []core.Event{{Type: "task_started", Task: task, Data: data}}
}

func TestUncoveredIsAHardFloor(t *testing.T) {
	full, reason := FullRunRequired(core.VerifySpec{FullRunWhen: []string{}}, []string{"x"}, []string{"x"}, core.ModeLight, false)
	assert.True(t, full)
	assert.Contains(t, reason, "uncovered_file")
}

func TestTreeChangedDuringRun(t *testing.T) {
	ctx := context.Background()
	run := func(visibleChanges, ignoredChanges bool) (Report, []core.Event) {
		j := &fakes.Journal{}
		s := &stub{name: "go", tests: []string{"./a"}, pass: true}
		in := orchInput(j, s)
		calls := map[bool]int{}
		in.Tree = func(_ context.Context, ign bool) (string, error) {
			calls[ign]++
			switch {
			case ign && ignoredChanges:
				return []string{"F0", "F1", "F2"}[calls[ign]-1], nil
			case !ign && visibleChanges:
				return []string{"V0", "V1"}[calls[ign]-1], nil
			case ign:
				return "FULL", nil
			}
			return "VIS", nil
		}
		rep, err := Run(ctx, in)
		require.NoError(t, err)
		ev, _ := j.Events(ctx, "t1")
		return rep, ev
	}

	rep, ev := run(true, false)
	assert.False(t, rep.Passed, "a visible change during the run is red")
	assert.Contains(t, string(ev[0].Data), `"passed":false`)

	rep, ev = run(false, true)
	assert.True(t, rep.Passed, "ignored files (caches) may change during the run")
	assert.Contains(t, string(ev[0].Data), `"tree":"F0"`, "the recorded tree is the full fingerprint taken after the run")
}

func TestTaskChanged(t *testing.T) {
	ctx := context.Background()
	root := testutil.GitRepo(t, map[string]string{
		"in/a.txt": "a content", "b.txt": "b", "gone.txt": "g", ".gitignore": "ign/\n", "ign/cache": "1",
	})
	write(t, root, map[string]string{"nested/.git/HEAD": "ref: x", "nested/f.txt": "1"})
	events := startedTask(t, root, "t1", []string{"in/**"})
	trust, err := LoadTrust(root, "t1", events)
	require.NoError(t, err)

	changed := func(ign bool) []string {
		c, err := TaskChanged(ctx, root, trust, ign)
		require.NoError(t, err)
		return c
	}
	assert.Empty(t, changed(true), "nothing changed since the baseline")

	require.NoError(t, os.MkdirAll(filepath.Join(root, "out"), 0o755))
	testutil.Git(t, root, "mv", "in/a.txt", "out/a.txt")
	assert.Equal(t, []string{"in/a.txt", "out/a.txt"}, changed(true), "a rename out of scope lists both paths")
	testutil.Git(t, root, "mv", "out/a.txt", "in/a.txt")

	testutil.Git(t, root, "update-index", "--assume-unchanged", "b.txt")
	write(t, root, map[string]string{
		"b.txt": "evil", ".rr/run/x.jsonl": "{}", "ign/cache": "poisoned", "nested/f.txt": "2", "new/n.txt": "n",
	})
	require.NoError(t, os.Remove(filepath.Join(root, "gone.txt")))
	assert.Equal(t, []string{"b.txt", "gone.txt", "ign/cache", "nested/f.txt", "new/n.txt"}, changed(true),
		"assume-unchanged, ignored, nested-repo, new and deleted paths all count; .rr/ does not")
	assert.NotContains(t, changed(false), "ign/cache", "ignored paths are left out of the selection input")
}

func TestTaskChangedRejectsOptionLikeBase(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"a": "1"})
	out := filepath.Join(t.TempDir(), "pwned")
	_, err := TaskChanged(context.Background(), root, Trust{BaseSHA: "--output=" + out}, true)
	require.Error(t, err)
	_, statErr := os.Stat(out)
	assert.True(t, os.IsNotExist(statErr), "the injected option must not run")
}

func TestLoadTrust(t *testing.T) {
	root := testutil.GitRepo(t, map[string]string{"a": "1"})
	ok := startedTask(t, root, "t1", []string{"src/**"})
	tr, err := LoadTrust(root, "t1", ok)
	require.NoError(t, err)
	assert.Equal(t, []string{"src/**"}, tr.Scope)

	var d map[string]any
	require.NoError(t, json.Unmarshal(ok[0].Data, &d))
	with := func(mutate func(map[string]any)) []core.Event {
		m := map[string]any{}
		for k, v := range d {
			m[k] = v
		}
		mutate(m)
		b, _ := json.Marshal(m)
		return []core.Event{{Type: "task_started", Data: b}}
	}
	tests := []struct {
		name   string
		events []core.Event
	}{
		{"no events", nil},
		{"no scope", with(func(m map[string]any) { delete(m, "scope") })},
		{"no base", with(func(m map[string]any) { delete(m, "base_sha") })},
		{"base not a full sha", with(func(m map[string]any) { m["base_sha"] = "HEAD" })},
		{"base option-like", with(func(m map[string]any) { m["base_sha"] = "--output=x" })},
		{"no baseline", with(func(m map[string]any) { delete(m, "baseline") })},
		{"baseline sha mismatch", with(func(m map[string]any) { m["baseline"] = "00" })},
		{"scope only in plan_accepted", []core.Event{
			with(func(m map[string]any) { delete(m, "scope") })[0],
			{Type: "plan_accepted", Data: []byte(`{"scope":["**"]}`)},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadTrust(root, "t1", tc.events)
			assert.Error(t, err)
		})
	}

	require.NoError(t, os.WriteFile(filepath.Join(journal.RunDir(root), "t1.baseline.json"), []byte(`{}`), 0o644))
	_, err = LoadTrust(root, "t1", ok)
	assert.Error(t, err, "a tampered manifest file is refused")
}

func TestTreeFingerprintSensitivity(t *testing.T) {
	ctx := context.Background()
	root := testutil.GitRepo(t, map[string]string{"a.txt": "a", ".gitignore": "ign/\n"})
	write(t, root, map[string]string{"nested/.git/HEAD": "x", "nested/f.txt": "1"})
	fp := func(ign bool) string {
		s, err := TreeFingerprint(ctx, root, ign)
		require.NoError(t, err)
		return s
	}
	full, vis := fp(true), fp(false)
	assert.Equal(t, full, fp(true), "stable")

	write(t, root, map[string]string{".rr/run/x": "noise"})
	assert.Equal(t, full, fp(true), ".rr/ is ignored")

	write(t, root, map[string]string{"ign/cache": "1"})
	assert.NotEqual(t, full, fp(true), "ignored files count in the full fingerprint")
	assert.Equal(t, vis, fp(false), "and not in the visible one")

	write(t, root, map[string]string{"nested/f.txt": "2"})
	assert.NotEqual(t, vis, fp(false), "nested repository content counts")

	before := fp(true)
	write(t, root, map[string]string{"a.txt": ""})
	empty := fp(true)
	require.NoError(t, os.Remove(filepath.Join(root, "a.txt")))
	assert.NotEqual(t, before, empty)
	assert.NotEqual(t, empty, fp(true), "deleted differs from empty")

	if os.Geteuid() != 0 {
		write(t, root, map[string]string{"locked.txt": "x"})
		require.NoError(t, os.Chmod(filepath.Join(root, "locked.txt"), 0))
		_, err := TreeFingerprint(ctx, root, true)
		assert.Error(t, err, "unreadable file must not be silent")
	}
}

// counting stub: safe for parallel Run
type parStub struct {
	runs atomic.Int32
}

func (s *parStub) Name() string       { return "go" }
func (s *parStub) Detect(string) bool { return true }
func (s *parStub) Map(context.Context, string, []string) ([]string, []string, error) {
	return []string{"./a"}, nil, nil
}
func (s *parStub) Run(context.Context, string, core.VerifyAdapterSpec, []string, bool) (core.TestResult, error) {
	s.runs.Add(1)
	return core.TestResult{Passed: true}, nil
}

func TestSuiteBudgetParallel(t *testing.T) {
	for name, j := range map[string]core.Journal{
		"fake": &fakes.Journal{},
		"real": journal.New(t.TempDir()),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if name == "real" { // the real journal needs task_started first
				_, err := j.Append(ctx, core.Event{Type: "task_started", Task: "t1", Actor: core.ActorHuman})
				require.NoError(t, err)
			}
			s := &parStub{}
			one := 1
			in := Input{Task: "t1", Changed: []string{"a.go"}, Journal: j, Actors: []core.VerifyAdapter{s}, Closing: true,
				Spec: core.VerifySpec{Adapters: []core.VerifyAdapterSpec{{Name: "go", Cmd: "x"}}, SuiteBudget: &one}}
			var wg sync.WaitGroup
			var refused atomic.Int32
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := Run(ctx, in); err != nil {
						assert.ErrorIs(t, err, ErrSuiteBudget)
						refused.Add(1)
					}
				}()
			}
			wg.Wait()
			assert.EqualValues(t, 1, s.runs.Load())
			assert.EqualValues(t, 3, refused.Load())
		})
	}
}

func TestUnsupportedAdapterRefusesFullRun(t *testing.T) {
	s := &stub{name: "go", tests: []string{"./a"}, pass: true}
	in := orchInput(&fakes.Journal{}, s)
	in.Spec.Adapters = append(in.Spec.Adapters, core.VerifyAdapterSpec{Name: "lint"}) // no built-in, no cmd

	_, err := Run(context.Background(), in) // affected: allowed
	require.NoError(t, err)

	in.Closing = true
	_, err = Run(context.Background(), in)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lint not supported")
	assert.Len(t, s.gotFull, 1, "nothing ran on the refused full run")
}

func TestOptionLikePathsRefused(t *testing.T) {
	ctx := context.Background()
	for _, a := range []core.VerifyAdapter{PHPUnit{}, Node{Tool: "jest"}, Node{Tool: "vitest"}, Pytest{}, Golang{}} {
		t.Run(a.Name(), func(t *testing.T) {
			rec := fakeRunner(t, "x")
			_, err := a.Run(ctx, t.TempDir(), core.VerifyAdapterSpec{Name: a.Name(), Cmd: "x"}, []string{"-rf", "ok"}, false)
			assert.Error(t, err)
			assert.Empty(t, calls(t, rec), "nothing may run")
		})
	}
	_, _, err := Node{Tool: "jest"}.Map(ctx, t.TempDir(), []string{"--config=evil.js"})
	assert.Error(t, err)
}

func TestTaskMode(t *testing.T) {
	ev := func(typ, mode string) core.Event {
		return core.Event{Type: typ, Data: []byte(`{"mode":"` + mode + `"}`)}
	}
	tests := []struct {
		name    string
		events  []core.Event
		want    core.Mode
		wantErr bool
	}{
		{"started only", []core.Event{ev("task_started", "light")}, core.ModeLight, false},
		{"rescored up", []core.Event{ev("task_started", "light"), ev("weight_rescored", "full")}, core.ModeFull, false},
		{"amended wins by rank, not order", []core.Event{ev("task_started", "guarded"), ev("weight_amended", "programme"), ev("weight_rescored", "full")}, core.ModeProgramme, false},
		{"never lowers", []core.Event{ev("task_started", "full"), ev("weight_amended", "light")}, core.ModeFull, false},
		{"unknown later value ignored", []core.Event{ev("task_started", "light"), ev("weight_rescored", "bogus")}, core.ModeLight, false},
		{"unknown started mode", []core.Event{ev("task_started", "bogus"), ev("weight_rescored", "full")}, "", true},
		{"no mode", []core.Event{{Type: "task_started", Data: []byte(`{}`)}}, "", true},
		{"no events", nil, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TaskMode(tc.events)
			assert.Equal(t, tc.wantErr, err != nil)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGenericAdapterRunsCmdOnFullOnly(t *testing.T) {
	ctx := context.Background()
	root := testutil.CopyFixture(t, "php-symfony")
	fixer := filepath.Join(root, "vendor/bin/php-cs-fixer")
	rec := filepath.Join(t.TempDir(), "fixer")
	require.NoError(t, os.MkdirAll(filepath.Dir(fixer), 0o755))
	require.NoError(t, os.WriteFile(fixer, []byte("#!/bin/sh\necho \"$@\" >> "+rec+"\nexit ${FIXER_EXIT:-0}\n"), 0o755))
	fakeRunner(t, "php")

	in := Input{
		Root: root, Task: "t1", Changed: []string{"src/Payment/PaymentService.php"}, Mode: core.ModeGuarded,
		Spec: core.VerifySpec{Adapters: []core.VerifyAdapterSpec{
			{Name: "phpunit", Cmd: "php bin/phpunit"},
			{Name: "lint", Cmd: "vendor/bin/php-cs-fixer fix --dry-run"},
		}},
	}
	rep, err := Run(ctx, in) // affected: lint is not executed
	require.NoError(t, err)
	assert.False(t, rep.Full)
	assert.True(t, rep.Passed)
	assert.NotContains(t, rep.Results, "lint")
	assert.Empty(t, calls(t, rec))

	in.Closing = true
	rep, err = Run(ctx, in)
	require.NoError(t, err)
	assert.True(t, rep.Passed)
	assert.Contains(t, rep.Results, "lint")
	assert.Equal(t, []string{"fix --dry-run"}, calls(t, rec))

	t.Setenv("FIXER_EXIT", "1")
	rep, err = Run(ctx, in)
	require.NoError(t, err)
	assert.False(t, rep.Passed, "a failing generic cmd turns the close red")
}
