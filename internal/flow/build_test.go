package flow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
)

func TestCheckPlanScope(t *testing.T) {
	scope := []string{"src/Payment/PaymentService.php", "src/Invoice/**"}
	for name, tc := range map[string]struct {
		plan string
		err  string
	}{
		"exact file":         {"steps:\n  - {id: a, files: [src/Payment/PaymentService.php]}\n", ""},
		"file under glob":    {"steps:\n  - {id: a, files: [src/Invoice/New.php], tests: [src/Invoice/Sub/X.php]}\n", ""},
		"outside":            {"steps:\n  - {id: a, files: [src/Security/Login.php]}\n", "outside the task scope"},
		"test outside":       {"steps:\n  - {id: a, files: [src/Invoice/A.php], tests: [tests/ATest.php]}\n", "outside the task scope"},
		"dir is not a file":  {"steps:\n  - {id: a, files: [src/Payment]}\n", "outside the task scope"},
		"escape":             {"steps:\n  - {id: a, files: [src/Invoice/../Security/L.php]}\n", "escapes"},
		"overlap w/o after":  {"steps:\n  - {id: a, files: [src/Invoice/A.php]}\n  - {id: b, files: [src/Invoice/A.php]}\n", "share"},
		"unknown key":        {"steps:\n  - {id: a, files: [src/Invoice/A.php], nope: 1}\n", "nope"},
		"absolute":           {"steps:\n  - {id: a, files: [/etc/passwd]}\n", "absolute"},
		"no steps parse err": {"steps: nope\n", "plan"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := checkPlan([]byte(tc.plan), scope, nil)
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestCacheDirOutsideCheckout(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	for name, tc := range map[string]struct {
		dir, home string
		err       string
	}{
		"default under home":  {"", home, ""},
		"explicit abs":        {filepath.Join(home, "c"), home, ""},
		"inside the checkout": {filepath.Join(root, ".cache"), home, "inside the checkout"},
		"relative":            {"cache", home, "absolute"},
		"no home":             {"", "", "home"},
	} {
		t.Run(name, func(t *testing.T) {
			var e Env
			e.Root, e.Home = root, tc.home
			e.Policy.Policy.Research.Cache.Dir = tc.dir
			dir, err := e.cacheDir()
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.True(t, filepath.IsAbs(dir))
			assert.NotContains(t, dir, "<repo-hash>")
		})
	}
}

type journalRecorder struct {
	types []string
	data  []ledger.WorkerData
}

func (j *journalRecorder) emit(_ context.Context, typ string, data any) error {
	j.types = append(j.types, typ)
	j.data = append(j.data, data.(ledger.WorkerData))
	return nil
}

func TestMeterPhasesAndUsage(t *testing.T) {
	use := core.Usage{Runtime: "codex", Model: "gpt-5", Input: 10, Output: 5}
	for role, phase := range map[string]string{
		"code-scout": "research", "prior-art-scout": "research", "implementer": "implement", "fixer": "implement",
		"reviewer-spec": "review", "reviewer-quality": "review",
	} {
		t.Run(role, func(t *testing.T) {
			rec := &journalRecorder{}
			inner := &fakes.WorkerRunner{Reports: []core.WorkerReport{{Status: core.StatusDone, Tokens: 15, Calls: 2, Usage: use}}}
			rep, err := Meter{Runtime: "codex", Emit: rec.emit}.Wrap(inner).Run(context.Background(), core.WorkerSpec{Role: role, Tier: core.TierBalanced})
			require.NoError(t, err)
			assert.Equal(t, core.StatusDone, rep.Status)
			require.Len(t, rec.data, 1)
			assert.Equal(t, ledger.EventWorker, rec.types[0])
			assert.Equal(t, ledger.WorkerData{Phase: phase, Role: role, Tier: core.TierBalanced, Runtime: "codex",
				Status: core.StatusDone, Tokens: 15, Calls: 2, Usage: use}, rec.data[0])
		})
	}
}

func TestMeterFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("unknown role is not run", func(t *testing.T) {
		rec, inner := &journalRecorder{}, &fakes.WorkerRunner{Reports: []core.WorkerReport{{Status: core.StatusDone}}}
		_, err := Meter{Emit: rec.emit}.Wrap(inner).Run(ctx, core.WorkerSpec{Role: "wizard"})
		require.Error(t, err)
		assert.Empty(t, inner.Specs)
	})
	t.Run("a failed run is journaled with unknown usage", func(t *testing.T) {
		rec := &journalRecorder{}
		_, err := Meter{Emit: rec.emit}.Wrap(&fakes.WorkerRunner{}).Run(ctx, core.WorkerSpec{Role: "implementer"})
		require.Error(t, err)
		require.Len(t, rec.data, 1)
		assert.Empty(t, rec.data[0].Usage.Model)
	})
	t.Run("a journal failure fails the run", func(t *testing.T) {
		m := Meter{Emit: func(context.Context, string, any) error { return errors.New("disk full") }}
		_, err := m.Wrap(&fakes.WorkerRunner{Reports: []core.WorkerReport{{Status: core.StatusDone}}}).Run(ctx, core.WorkerSpec{Role: "implementer"})
		require.ErrorContains(t, err, "disk full")
	})
}

type roFake struct{ r core.WorkerRunner }

func (f roFake) ReadOnly() core.WorkerRunner { return f.r }

func TestMeterWrapROMetersReviewers(t *testing.T) {
	rec := &journalRecorder{}
	ro := Meter{Emit: rec.emit}.WrapRO(roFake{&fakes.WorkerRunner{Reports: []core.WorkerReport{{Status: core.StatusDone}}}})
	_, err := ro.ReadOnly().Run(context.Background(), core.WorkerSpec{Role: "reviewer-spec"})
	require.NoError(t, err)
	require.Len(t, rec.data, 1)
	assert.Equal(t, "review", rec.data[0].Phase)
}
