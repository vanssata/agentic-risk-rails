package sync_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
)

func TestRenderWriteDrift(t *testing.T) {
	root := t.TempDir()
	gens := []core.Generator{
		fakes.Generator{ID: "b", Files: []core.File{{Path: "b/x.json", Content: []byte("{}")}}},
		fakes.Generator{ID: "a", Files: []core.File{{Path: "a.toml", Content: []byte("x=1")}}},
	}
	files, err := rrsync.Render(context.Background(), core.SyncInput{}, gens)
	require.NoError(t, err)
	assert.Equal(t, "a.toml", files[0].Path)

	drift, err := rrsync.Drift(root, files)
	require.NoError(t, err)
	assert.Len(t, drift, 2, "missing files are drift")

	require.NoError(t, rrsync.Write(root, files))
	drift, err = rrsync.Drift(root, files)
	require.NoError(t, err)
	assert.Empty(t, drift)
}

func TestRenderRejectsDuplicatesAndEscapes(t *testing.T) {
	ctx := context.Background()
	dup := []core.Generator{
		fakes.Generator{ID: "a", Files: []core.File{{Path: "x"}}},
		fakes.Generator{ID: "b", Files: []core.File{{Path: "./x"}}},
	}
	_, err := rrsync.Render(ctx, core.SyncInput{}, dup)
	assert.ErrorContains(t, err, "both a and b")

	for _, p := range []string{"../evil", "/etc/passwd", "a/../../evil"} {
		_, err = rrsync.Render(ctx, core.SyncInput{}, []core.Generator{fakes.Generator{ID: "e", Files: []core.File{{Path: p}}}})
		assert.ErrorContains(t, err, "escapes", p)
	}
}
