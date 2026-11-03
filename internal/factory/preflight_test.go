package factory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// fakeExec fails every command line that contains a key of fail.
type fakeExec struct{ fail []string }

func (f *fakeExec) run(_ context.Context, _ []string, name string, args ...string) error {
	line := name + " " + strings.Join(args, " ")
	for _, sub := range f.fail {
		if strings.Contains(line, sub) {
			return errors.New("exit status 1")
		}
	}
	return nil
}

func trustFile(t *testing.T, dir, root string, trusted bool) {
	t.Helper()
	v := "false"
	if trusted {
		v = "true"
	}
	b := `{"projects":{"` + root + `":{"hasTrustDialogAccepted":` + v + `}}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(b), 0o600))
}

func refusal(t *testing.T, err error) *core.Refusal {
	t.Helper()
	var r *core.Refusal
	require.ErrorAs(t, err, &r)
	return r
}

func TestPreflightClaude(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	in := func(cfg string) PreflightIn {
		return PreflightIn{Runtime: "claude", Root: root, ConfigDir: cfg, Home: t.TempDir()}
	}
	t.Run("untrusted repo", func(t *testing.T) {
		cfg := t.TempDir()
		trustFile(t, cfg, root, false)
		r := refusal(t, preflight(context.Background(), in(cfg), (&fakeExec{}).run))
		assert.Equal(t, "PREFLIGHT", r.Code)
		assert.Contains(t, r.Detail, "trust")
		assert.Contains(t, r.Detail, root) // names the path to trust
	})
	t.Run("no config file", func(t *testing.T) {
		r := refusal(t, preflight(context.Background(), in(t.TempDir()), (&fakeExec{}).run))
		assert.Equal(t, "PREFLIGHT", r.Code)
	})
	t.Run("default config dir is HOME", func(t *testing.T) {
		home := t.TempDir()
		trustFile(t, home, root, true)
		p := PreflightIn{Runtime: "claude", Root: root, Home: home}
		assert.NoError(t, preflight(context.Background(), p, (&fakeExec{fail: []string{"/denied"}}).run))
	})
	t.Run("sandbox cannot run a command", func(t *testing.T) {
		cfg := t.TempDir()
		trustFile(t, cfg, root, true)
		r := refusal(t, preflight(context.Background(), in(cfg), (&fakeExec{fail: []string{"unshare -U"}}).run))
		assert.Equal(t, "PREFLIGHT", r.Code)
		assert.Contains(t, r.Detail, "sandbox")
	})
	t.Run("sandbox does not confine writes (negative control)", func(t *testing.T) {
		cfg := t.TempDir()
		trustFile(t, cfg, root, true)
		// every command succeeds, also the write that must fail
		r := refusal(t, preflight(context.Background(), in(cfg), (&fakeExec{}).run))
		assert.Contains(t, r.Detail, "confine")
	})
	t.Run("positive control fails (every write fails, not only the denied one)", func(t *testing.T) {
		cfg := t.TempDir()
		trustFile(t, cfg, root, true)
		r := refusal(t, preflight(context.Background(), in(cfg), (&fakeExec{fail: []string{"touch"}}).run))
		assert.Contains(t, r.Detail, "writable bind")
	})
	t.Run("works", func(t *testing.T) {
		cfg := t.TempDir()
		trustFile(t, cfg, root, true)
		assert.NoError(t, preflight(context.Background(), in(cfg), (&fakeExec{fail: []string{"/denied"}}).run))
	})
}

func TestPreflightCodex(t *testing.T) {
	in := func() PreflightIn { return PreflightIn{Runtime: "codex", Root: t.TempDir(), Home: t.TempDir()} }
	t.Run("works", func(t *testing.T) {
		assert.NoError(t, preflight(context.Background(), in(), (&fakeExec{fail: []string{".rr-preflight-deny"}}).run))
	})
	t.Run("sandbox broken", func(t *testing.T) {
		r := refusal(t, preflight(context.Background(), in(), (&fakeExec{fail: []string{"codex"}}).run))
		assert.Equal(t, "PREFLIGHT", r.Code)
		assert.Contains(t, r.Detail, "sandbox")
	})
	t.Run("sandbox lets a write outside the workspace through", func(t *testing.T) {
		r := refusal(t, preflight(context.Background(), in(), (&fakeExec{}).run))
		assert.Contains(t, r.Detail, "confine")
	})
}

func TestPreflightFailClosed(t *testing.T) {
	for _, rt := range []string{"", "gemini"} {
		r := refusal(t, preflight(context.Background(), PreflightIn{Runtime: rt, Root: t.TempDir(), Home: t.TempDir()}, (&fakeExec{}).run))
		assert.Equal(t, "PREFLIGHT", r.Code)
	}
}
