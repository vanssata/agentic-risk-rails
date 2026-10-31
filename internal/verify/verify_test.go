package verify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

// fakeRunner installs a binary that appends its argv to a record file and
// exits with $FAKE_EXIT (default 0). It returns the record path.
func fakeRunner(t *testing.T, name string) string {
	t.Helper()
	rec := filepath.Join(t.TempDir(), "calls")
	t.Setenv("FAKE_REC", rec)
	testutil.FakeBin(t, name, `echo "$@" >> "$FAKE_REC"; exit ${FAKE_EXIT:-0}`)
	return rec
}

func calls(t *testing.T, rec string) []string {
	b, err := os.ReadFile(rec)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(c), 0o644))
	}
}

func TestFullRunRequired(t *testing.T) {
	spec := core.VerifySpec{FullRunWhen: []string{"lockfile", "config/**", ".github/**", "migrations/**", "uncovered_file", "mode>=full", "close"}}
	tests := []struct {
		name      string
		changed   []string
		uncovered []string
		mode      core.Mode
		closing   bool
		want      bool
	}{
		{"plain source", []string{"src/A.php"}, nil, core.ModeGuarded, false, false},
		{"lockfile", []string{"composer.lock"}, nil, core.ModeLight, false, true},
		{"nested lockfile", []string{"web/package-lock.json"}, nil, core.ModeLight, false, true},
		{"config glob", []string{"config/packages/x.yaml"}, nil, core.ModeLight, false, true},
		{"ci glob", []string{".github/workflows/ci.yml"}, nil, core.ModeLight, false, true},
		{"migration", []string{"migrations/V1.php"}, nil, core.ModeLight, false, true},
		{"uncovered", []string{"src/B.php"}, []string{"src/B.php"}, core.ModeLight, false, true},
		{"mode full", []string{"src/A.php"}, nil, core.ModeFull, false, true},
		{"mode programme", []string{"src/A.php"}, nil, core.ModeProgramme, false, true},
		{"close", []string{"src/A.php"}, nil, core.ModeLight, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := FullRunRequired(spec, tc.changed, tc.uncovered, tc.mode, tc.closing)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want, reason != "")
		})
	}
	// close is a floor even when full_run_when omits it
	got, _ := FullRunRequired(core.VerifySpec{}, nil, nil, core.ModeLight, true)
	assert.True(t, got)
}

func TestPHPUnitFixture(t *testing.T) {
	root := testutil.Fixture(t, "php-symfony")
	tests, unc, err := PHPUnit{}.Map(context.Background(), root,
		[]string{"src/Payment/PaymentService.php", "src/Controller/HomeController.php", "templates/base.html.twig"})
	require.NoError(t, err)
	assert.Equal(t, []string{"tests/Payment/PaymentServiceTest.php"}, tests)
	assert.Equal(t, []string{"src/Controller/HomeController.php", "templates/base.html.twig"}, unc)

	tests, unc, err = PHPUnit{}.Map(context.Background(), root, []string{"tests/Payment/PaymentServiceTest.php"})
	require.NoError(t, err)
	assert.Equal(t, []string{"tests/Payment/PaymentServiceTest.php"}, tests)
	assert.Empty(t, unc)
}

func TestPHPUnitRunAndNoFakeGreen(t *testing.T) {
	rec := fakeRunner(t, "php")
	spec := core.VerifyAdapterSpec{Name: "phpunit", Cmd: "php bin/phpunit"}
	root := t.TempDir()

	res, err := PHPUnit{}.Run(context.Background(), root, spec, nil, false)
	require.NoError(t, err)
	assert.False(t, res.Passed, "empty non-full selection must not be green")
	assert.Empty(t, calls(t, rec), "nothing may run")

	res, err = PHPUnit{}.Run(context.Background(), root, spec, []string{"tests/ATest.php"}, false)
	require.NoError(t, err)
	assert.True(t, res.Passed)
	assert.Equal(t, []string{"bin/phpunit tests/ATest.php"}, calls(t, rec))

	t.Setenv("FAKE_EXIT", "1")
	res, err = PHPUnit{}.Run(context.Background(), root, spec, []string{"tests/ATest.php"}, false)
	require.NoError(t, err)
	assert.False(t, res.Passed)
	assert.Equal(t, []string{"tests/ATest.php"}, res.Failed)

	res, err = PHPUnit{}.Run(context.Background(), root, spec, nil, true)
	require.NoError(t, err)
	assert.False(t, res.Passed)
	c := calls(t, rec)
	assert.Equal(t, "bin/phpunit", c[len(c)-1], "full run passes no test args")
}

func TestNodeJest(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"package.json": `{"devDependencies":{"jest":"1"}}`})
	// fake npx: lists a test only for src/a.js
	testutil.FakeBin(t, "npx", `case "$*" in *src/a.js) echo "`+root+`/src/a.test.js";; esac`)
	assert.True(t, Node{Tool: "jest"}.Detect(root))
	assert.False(t, Node{Tool: "vitest"}.Detect(root))

	tests, unc, err := Node{Tool: "jest"}.Map(context.Background(), root, []string{"src/a.js", "src/b.js", "src/c.spec.ts"})
	require.NoError(t, err)
	assert.Equal(t, []string{"src/a.test.js", "src/c.spec.ts"}, tests)
	assert.Equal(t, []string{"src/b.js"}, unc)
}

func TestNodeVitestRun(t *testing.T) {
	rec := fakeRunner(t, "npx")
	spec := core.VerifyAdapterSpec{Name: "vitest", Cmd: "npx vitest"}
	a := Node{Tool: "vitest"}
	tests, unc, err := a.Map(context.Background(), t.TempDir(), []string{"src/a.ts"})
	require.NoError(t, err)
	assert.Empty(t, unc)
	res, err := a.Run(context.Background(), t.TempDir(), spec, tests, false)
	require.NoError(t, err)
	assert.True(t, res.Passed)
	assert.Equal(t, []string{"vitest related --run src/a.ts"}, calls(t, rec))
}

func TestPytestImportGraph(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"pyproject.toml":          "[tool.pytest.ini_options]\n",
		"src/app/__init__.py":     "",
		"src/app/core.py":         "def f(): pass\n",
		"src/app/service.py":      "from app import core\n",
		"src/app/orphan.py":       "x = 1\n",
		"tests/test_service.py":   "import app.service\n",
		"tests/test_core.py":      "from app.core import f\n",
		"tests/test_unrelated.py": "import os\n",
	})
	assert.True(t, Pytest{}.Detect(root))
	tests, unc, err := Pytest{}.Map(context.Background(), root, []string{"src/app/core.py", "src/app/orphan.py", "README.md"})
	require.NoError(t, err)
	assert.Equal(t, []string{"tests/test_core.py", "tests/test_service.py"}, tests, "transitive: core <- service <- test_service")
	assert.Equal(t, []string{"README.md", "src/app/orphan.py"}, unc)
}

func TestGoRealRepo(t *testing.T) {
	root := testutil.RepoRoot(t)
	tests, unc, err := Golang{}.Map(context.Background(), root, []string{"internal/globs/globs.go"})
	require.NoError(t, err)
	assert.Empty(t, unc)
	assert.Contains(t, tests, "./internal/globs", "own tests")
	assert.Contains(t, tests, "./internal/guard", "guard imports globs")
	assert.Contains(t, tests, "./internal/policy", "policy imports globs")
	assert.NotContains(t, tests, "./internal/journal", "journal does not depend on globs")

	_, unc, err = Golang{}.Map(context.Background(), root, []string{"nonexistent-dir/x.txt"})
	require.NoError(t, err)
	assert.Equal(t, []string{"nonexistent-dir/x.txt"}, unc)
}

func TestGoRun(t *testing.T) {
	rec := fakeRunner(t, "go")
	spec := core.VerifyAdapterSpec{Name: "go", Cmd: "go test"}
	res, err := Golang{}.Run(context.Background(), t.TempDir(), spec, []string{"./a", "./b"}, false)
	require.NoError(t, err)
	assert.True(t, res.Passed)
	assert.Equal(t, []string{"test ./a ./b"}, calls(t, rec))
}

// stub adapter for orchestration tests
type stub struct {
	name      string
	tests     []string
	uncovered []string
	pass      bool
	gotFull   []bool
}

func (s *stub) Name() string       { return s.name }
func (s *stub) Detect(string) bool { return true }
func (s *stub) Map(context.Context, string, []string) ([]string, []string, error) {
	return s.tests, s.uncovered, nil
}
func (s *stub) Run(_ context.Context, _ string, _ core.VerifyAdapterSpec, tests []string, full bool) (core.TestResult, error) {
	s.gotFull = append(s.gotFull, full)
	return core.TestResult{Passed: s.pass, Ran: tests}, nil
}

func yes() *bool { b := true; return &b }
func two() *int  { n := 2; return &n }

func orchInput(j core.Journal, s *stub) Input {
	return Input{
		Root: t0, Task: "t1", Changed: []string{"a.go"}, Journal: j, Actors: []core.VerifyAdapter{s}, Tree: func(context.Context, bool) (string, error) { return "T1", nil },
		Spec: core.VerifySpec{
			Adapters:              []core.VerifyAdapterSpec{{Name: s.name, Cmd: "x"}},
			FullRunWhen:           []string{"uncovered_file", "close"},
			SuiteBudget:           two(),
			SelectionMissesMetric: yes(),
		},
		Mode: core.ModeGuarded,
	}
}

const t0 = "."

func TestRunOrchestration(t *testing.T) {
	ctx := context.Background()

	t.Run("affected then uncovered goes full", func(t *testing.T) {
		j := &fakes.Journal{}
		s := &stub{name: "go", tests: []string{"./a"}, pass: true}
		rep, err := Run(ctx, orchInput(j, s))
		require.NoError(t, err)
		assert.False(t, rep.Full)
		assert.True(t, rep.Passed)

		s.uncovered = []string{"x.txt"}
		rep, err = Run(ctx, orchInput(j, s))
		require.NoError(t, err)
		assert.True(t, rep.Full)
		assert.Contains(t, rep.Reason, "uncovered_file")
		assert.Equal(t, []bool{false, true}, s.gotFull)
	})

	t.Run("empty selection is not green", func(t *testing.T) {
		s := &stub{name: "go", pass: false}
		rep, err := Run(ctx, orchInput(&fakes.Journal{}, s))
		require.NoError(t, err)
		assert.False(t, rep.Passed)
	})

	t.Run("selection miss recorded", func(t *testing.T) {
		j := &fakes.Journal{}
		s := &stub{name: "go", tests: []string{"./a"}, pass: true}
		_, err := Run(ctx, orchInput(j, s))
		require.NoError(t, err)
		s.pass = false
		in := orchInput(j, s)
		in.Closing = true
		rep, err := Run(ctx, in)
		require.NoError(t, err)
		assert.True(t, rep.Full)
		assert.Equal(t, []string{"verify_run", "verify_started", "verify_run", "selection_misses"}, j.Types("t1"))
	})

	t.Run("no miss when full is green or previous was not affected-green", func(t *testing.T) {
		j := &fakes.Journal{}
		s := &stub{name: "go", tests: []string{"./a"}, pass: false}
		in := orchInput(j, s)
		in.Closing = true
		_, err := Run(ctx, in)
		require.NoError(t, err)
		assert.Equal(t, []string{"verify_started", "verify_run"}, j.Types("t1"))
	})

	t.Run("suite budget", func(t *testing.T) {
		j := &fakes.Journal{}
		s := &stub{name: "go", tests: []string{"./a"}, pass: true}
		in := orchInput(j, s)
		in.Closing = true
		for i := 0; i < 2; i++ {
			_, err := Run(ctx, in)
			require.NoError(t, err)
		}
		_, err := Run(ctx, in)
		assert.ErrorIs(t, err, ErrSuiteBudget)
		assert.Len(t, s.gotFull, 2, "third full run must not execute")
		in.Closing = false
		_, err = Run(ctx, in) // affected runs are not budgeted
		assert.NoError(t, err)
	})

	t.Run("no configured adapter", func(t *testing.T) {
		in := orchInput(&fakes.Journal{}, &stub{name: "go"})
		in.Spec.Adapters = []core.VerifyAdapterSpec{{Name: "lint", Cmd: "x"}}
		_, err := Run(ctx, in)
		assert.Error(t, err)
	})
}

func TestComputeFacts(t *testing.T) {
	ev := func(d string) core.Event { return core.Event{Type: "verify_run", Data: []byte(d)} }
	green := ev(`{"full":true,"passed":true,"tree":"T1"}`)
	tests := []struct {
		name    string
		events  []core.Event
		tree    string
		changed []string
		want    Facts
	}{
		{"both", []core.Event{green}, "T1", []string{"src/a.go"}, Facts{GreenNow: true, InScope: true}},
		{"tree changed after run", []core.Event{green}, "T2", []string{"src/a.go"}, Facts{InScope: true}},
		{"affected only", []core.Event{ev(`{"full":false,"passed":true,"tree":"T1"}`)}, "T1", nil, Facts{InScope: true}},
		{"latest full red", []core.Event{green, ev(`{"full":true,"passed":false,"tree":"T1"}`)}, "T1", nil, Facts{InScope: true}},
		{"no runs", nil, "T1", nil, Facts{InScope: true}},
		{"out of scope", []core.Event{green}, "T1", []string{"src/a.go", "docs/x.md"}, Facts{GreenNow: true, OutOfScope: []string{"docs/x.md"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeFacts(tc.events, tc.tree, tc.changed, []string{"src/**"})
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want.GreenNow && tc.want.InScope, got.Ok())
		})
	}
}
