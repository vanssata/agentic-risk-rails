package degrade

import (
	"bytes"
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

func render(t *testing.T, root string) map[string]core.File {
	t.Helper()
	in := core.SyncInput{Root: root, Policy: fakes.StrictPolicy(), Level: core.L1}
	fs, err := Gen{}.Render(context.Background(), in)
	require.NoError(t, err)
	out := map[string]core.File{}
	for _, f := range fs {
		out[f.Path] = f
	}
	return out
}

func TestGoldens(t *testing.T) {
	files := render(t, t.TempDir())
	require.Len(t, files, 2)
	testutil.Golden(t, "AGENTS.md", files["AGENTS.md"].Content)
	testutil.Golden(t, "pre-commit", files[".githooks/pre-commit"].Content)
	assert.Equal(t, uint32(0o755), files[".githooks/pre-commit"].Mode)
}

func TestAgentsMDMarkers(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "AGENTS.md")

	require.NoError(t, os.WriteFile(path, []byte("# Mine\n\nno markers\n"), 0o644))
	assert.NotContains(t, render(t, root), "AGENTS.md", "a hand-written AGENTS.md is never touched")

	first := render(t, t.TempDir())["AGENTS.md"].Content
	stale := "# Mine\n\n" + begin + "\nold\n" + end + "\ntail\n"
	require.NoError(t, os.WriteFile(path, []byte(stale), 0o644))
	got := string(render(t, root)["AGENTS.md"].Content)
	assert.True(t, bytes.HasPrefix([]byte(got), []byte("# Mine\n\n"+begin)))
	assert.Contains(t, got, "tail")
	assert.NotContains(t, got, "\nold\n")
	assert.Contains(t, got, "rr guard --staged")

	require.NoError(t, os.WriteFile(path, first, 0o644))
	assert.Equal(t, first, render(t, root)["AGENTS.md"].Content, "idempotent")
}

func TestNoHooks(t *testing.T) {
	n := NoHooks{ID: "x"}
	e, err := n.Enforcement(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, core.EnforcementCIOnly, e)
	_, err = n.ParseHookInput("PreToolUse", bytes.NewReader(nil))
	assert.Error(t, err)
	var out, errb bytes.Buffer
	code, _ := n.RenderHookOutput("PreToolUse", core.ToolCall{}, core.Verdict{Decision: core.Ask}, &out, &errb)
	assert.Equal(t, 2, code)
}
