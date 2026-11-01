package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
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
	run := func(after string, actor core.Actor) (Report, []core.Event) {
		j := &fakes.Journal{}
		s := &stub{name: "go", tests: []string{"./a"}, pass: true}
		in := orchInput(j, s)
		in.Actor = actor
		n := 0
		in.Tree = func(context.Context) (string, error) {
			n++
			if n == 1 {
				return "BEFORE", nil
			}
			return after, nil
		}
		rep, err := Run(ctx, in)
		require.NoError(t, err)
		ev, _ := j.Events(ctx, "t1")
		return rep, ev
	}

	rep, ev := run("AFTER", "")
	assert.False(t, rep.Passed, "any non-cache change during the run is red")
	assert.Contains(t, string(ev[0].Data), `"passed":false`)

	rep, ev = run("BEFORE", "")
	assert.True(t, rep.Passed)
	assert.Contains(t, string(ev[0].Data), `"tree":"BEFORE"`, "the recorded tree is the one taken BEFORE the run")
	assert.Contains(t, string(ev[0].Data), `"trusted":false`, "an agent-started run is advisory")
	assert.Equal(t, core.ActorAgent, ev[0].Actor)

	_, ev = run("BEFORE", core.ActorAutonomy)
	assert.Contains(t, string(ev[0].Data), `"trusted":true`)
	_, ev = run("BEFORE", core.ActorHuman)
	assert.Contains(t, string(ev[0].Data), `"trusted":true`)
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
	root := testutil.GitRepo(t, map[string]string{"a.txt": "a", ".gitignore": "ign/\n.pytest_cache/\n"})
	write(t, root, map[string]string{"nested/.git/HEAD": "x", "nested/f.txt": "1"})
	fp := func() string {
		s, err := TreeFingerprint(ctx, root)
		require.NoError(t, err)
		return s
	}
	base := fp()
	assert.Equal(t, base, fp(), "stable")

	write(t, root, map[string]string{".rr/run/x": "noise"})
	assert.Equal(t, base, fp(), ".rr/ is ignored")

	for _, cache := range []string{".pytest_cache/v/x", "pkg/__pycache__/m.pyc", ".phpunit.cache/r", ".phpunit.result.cache", "node_modules/.cache/b", "var/cache/c"} {
		write(t, root, map[string]string{cache: "1"})
		assert.Equal(t, base, fp(), "built-in cache %s does not change the fingerprint", cache)
	}

	write(t, root, map[string]string{"ign/data": "1"})
	withIgnored := fp()
	assert.NotEqual(t, base, withIgnored, "other ignored files count")
	write(t, root, map[string]string{"ign/data": "2"})
	assert.NotEqual(t, withIgnored, fp())

	write(t, root, map[string]string{"nested/f.txt": "2"})
	assert.NotEqual(t, withIgnored, fp(), "nested repository content counts")

	before := fp()
	write(t, root, map[string]string{"a.txt": ""})
	empty := fp()
	require.NoError(t, os.Remove(filepath.Join(root, "a.txt")))
	assert.NotEqual(t, before, empty)
	assert.NotEqual(t, empty, fp(), "deleted differs from empty")

	if os.Geteuid() != 0 {
		write(t, root, map[string]string{"locked.txt": "x"})
		require.NoError(t, os.Chmod(filepath.Join(root, "locked.txt"), 0))
		_, err := TreeFingerprint(ctx, root)
		assert.Error(t, err, "unreadable file must not be silent")
	}
}

func TestFingerprintRefusesUnsafeEntries(t *testing.T) {
	ctx := context.Background()
	root := testutil.GitRepo(t, map[string]string{"a.txt": "a"})
	outside := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outside, []byte("s"), 0o644))

	require.NoError(t, os.Symlink("a.txt", filepath.Join(root, "inside-link")))
	_, err := TreeFingerprint(ctx, root)
	require.NoError(t, err, "a symlink that stays inside the repository is fine")

	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape-link")))
	_, err = TreeFingerprint(ctx, root)
	require.Error(t, err, "a symlink pointing outside the repository is refused")
	_, _, err = Baseline(ctx, root)
	require.Error(t, err)
	require.NoError(t, os.Remove(filepath.Join(root, "escape-link")))

	require.NoError(t, syscall.Mkfifo(filepath.Join(root, "pipe"), 0o644))
	_, err = TreeFingerprint(ctx, root)
	require.Error(t, err, "a FIFO is refused, not opened")
}

func TestReadFileIsFailClosed(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"ok.txt": "fine"})
	got, err := readFile(root, "ok.txt")
	require.NoError(t, err)
	assert.Equal(t, "fine", got)

	outside := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outside, []byte("s"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))
	_, err = readFile(root, "link")
	assert.Error(t, err)

	require.NoError(t, syscall.Mkfifo(filepath.Join(root, "pipe"), 0o644))
	_, err = readFile(root, "pipe")
	assert.Error(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(root, "big"), make([]byte, maxReadSize+1), 0o644))
	_, err = readFile(root, "big")
	assert.Error(t, err)
}

func TestAdapterEnvAndPathAreSanitized(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	rec := filepath.Join(t.TempDir(), "env")
	testutil.FakeBin(t, "tool", `env > "`+rec+`"`)
	t.Setenv("GOFLAGS", "-run=^$")
	t.Setenv("PYTEST_ADDOPTS", "-k nothing")
	t.Setenv("NODE_OPTIONS", "--require evil.js")
	t.Setenv("PHPUNIT_FILTER", "none")
	t.Setenv("CGO_CFLAGS", "-evil")
	t.Setenv("HOME", "/home/x")

	res, err := runCmd(ctx, root, core.VerifyAdapterSpec{Name: "t", Cmd: "tool"}, nil, true)
	require.NoError(t, err)
	require.True(t, res.Passed)
	b, err := os.ReadFile(rec)
	require.NoError(t, err)
	env := string(b)
	for _, bad := range []string{"GOFLAGS", "PYTEST_ADDOPTS", "NODE_OPTIONS", "PHPUNIT_FILTER", "CGO_CFLAGS"} {
		assert.NotContains(t, env, bad)
	}
	assert.Contains(t, env, "HOME=/home/x")
	assert.Contains(t, env, "PATH=")
}

func TestPlantedBinaryInRepoIsNotUsed(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(t.TempDir(), "planted-ran")
	write(t, root, map[string]string{"bin/go": "#!/bin/sh\ntouch " + marker + "\nexit 1\n"})
	require.NoError(t, os.Chmod(filepath.Join(root, "bin/go"), 0o755))
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+"relative/dir"+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, err := runCmd(context.Background(), root, core.VerifyAdapterSpec{Name: "go", Cmd: "go version"}, nil, true)
	require.NoError(t, err)
	assert.True(t, res.Passed, "the real go ran")
	_, statErr := os.Stat(marker)
	assert.True(t, os.IsNotExist(statErr), "the planted binary must not run")
}

func TestGoFlagsEnvHasNoEffect(t *testing.T) {
	// GOFLAGS=-run=^$ would make every `go test` pass without running a test.
	root := t.TempDir()
	write(t, root, map[string]string{
		"go.mod":    "module m\n\ngo 1.21\n",
		"m_test.go": "package m\nimport \"testing\"\nfunc TestFails(t *testing.T) { t.Fatal(\"boom\") }\n",
	})
	t.Setenv("GOFLAGS", "-run=^$")
	res, err := runCmd(context.Background(), root, core.VerifyAdapterSpec{Name: "go", Cmd: "go test ./..."}, nil, true)
	require.NoError(t, err)
	assert.False(t, res.Passed, "the failing test must still run and fail")
}

func TestCloseSkipsMapAndIsHostOnly(t *testing.T) {
	ctx := context.Background()
	root := testutil.GitRepo(t, map[string]string{"in/a.txt": "a", ".gitignore": "ign/\n.pytest_cache/\n"})
	events := startedTask(t, root, "t1", []string{"in/**"})
	trust, err := LoadTrust(root, "t1", events)
	require.NoError(t, err)

	mk := func(pass bool, mutate func()) (*mapSpy, CloseInput, *fakes.Journal) {
		j := &fakes.Journal{}
		sp := &mapSpy{stub: stub{name: "go", pass: pass}, mutate: mutate}
		return sp, CloseInput{Root: root, Task: "t1", Mode: core.ModeGuarded, Trust: trust, Journal: j, Actors: []core.VerifyAdapter{sp},
			Spec: core.VerifySpec{Adapters: []core.VerifyAdapterSpec{{Name: "go", Cmd: "x"}}}}, j
	}

	sp, in, j := mk(true, nil)
	in.Actor = core.ActorAutonomy
	f, err := Close(ctx, in)
	require.NoError(t, err)
	assert.True(t, f.GreenNow)
	assert.True(t, f.InScope)
	assert.Zero(t, sp.maps, "a close run does not map")
	ev, _ := j.Events(ctx, "t1")
	assert.Contains(t, string(ev[len(ev)-1].Data), `"trusted":true`)

	// facts come from this run: an agent actor can never produce a green fact
	_, in, j = mk(true, nil)
	in.Actor = core.ActorAgent
	f, err = Close(ctx, in)
	require.NoError(t, err)
	assert.False(t, f.GreenNow)
	ev, _ = j.Events(ctx, "t1")
	assert.Contains(t, string(ev[len(ev)-1].Data), `"trusted":false`)

	// F1: a test that deletes an ignored generated file (outside the cache allowlist) is red
	write(t, root, map[string]string{"ign/zz_gen_test.go": "x"})
	_, in, _ = mk(true, func() { _ = os.Remove(filepath.Join(root, "ign/zz_gen_test.go")) })
	in.Actor = core.ActorAutonomy
	in.Trust.Manifest = nil // baseline irrelevant here: only the during-run change matters
	f, err = Close(ctx, in)
	require.NoError(t, err)
	assert.False(t, f.GreenNow, "self-deleting ignored file => passed=false")

	// F5: an honest cache write stays green and in scope
	_, in, _ = mk(true, func() { write(t, root, map[string]string{".pytest_cache/v/cache/x": "1"}) })
	in.Actor = core.ActorAutonomy
	trust2, err := LoadTrust(root, "t1", startedTask(t, root, "t1", []string{"in/**", "ign/**"}))
	require.NoError(t, err)
	in.Trust = trust2
	f, err = Close(ctx, in)
	require.NoError(t, err)
	assert.True(t, f.GreenNow, "built-in cache writes do not turn the run red")
	assert.True(t, f.InScope, "and are not task changes")
}

type mapSpy struct {
	stub
	maps   int
	mutate func()
}

func (m *mapSpy) Map(ctx context.Context, r string, c []string) ([]string, []string, error) {
	m.maps++
	return m.stub.Map(ctx, r, c)
}

func (m *mapSpy) Run(ctx context.Context, r string, s core.VerifyAdapterSpec, tests []string, full bool) (core.TestResult, error) {
	if m.mutate != nil {
		m.mutate()
	}
	return m.stub.Run(ctx, r, s, tests, full)
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
	require.NoError(t, os.WriteFile(fixer, []byte("#!/bin/sh\necho \"$@\" >> "+rec+"\n[ -e "+rec+".fail ] && exit 1\nexit 0\n"), 0o755))
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

	failFlag(t, rec)
	rep, err = Run(ctx, in)
	require.NoError(t, err)
	assert.False(t, rep.Passed, "a failing generic cmd turns the close red")
}
