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

func TestRenderFiltersByRuntime(t *testing.T) {
	gen := func(id, path string) core.Generator {
		return fakes.Generator{ID: id, Files: []core.File{{Path: path}}}
	}
	ga, gb, gn := gen("rt-a-gen", "a"), gen("rt-b-gen", "b"), gen("neutral-gen", "n")
	rrsync.RegisterRuntime("rt-a", ga)
	rrsync.RegisterRuntime("rt-b", gb)
	rrsync.Register(gn)
	all := []core.Generator{ga, gb, gn}
	for _, c := range []struct {
		name string
		rts  []string
		want []string
		err  string
	}{
		{"nil renders all", nil, []string{"a", "b", "n"}, ""},
		{"subset", []string{"rt-b"}, []string{"b", "n"}, ""},
		{"empty list keeps only neutral", []string{}, []string{"n"}, ""},
		{"unknown name fails closed", []string{"rt-a", "nope"}, nil, `unknown runtime "nope"`},
		{"names are case-sensitive", []string{"RT-A"}, nil, `unknown runtime "RT-A"`},
		{"name with a space", []string{"rt a"}, nil, `unknown runtime "rt a"`},
		{"unknown name fails even with no generators", []string{"nope"}, nil, `unknown runtime "nope"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			var in core.SyncInput
			in.Policy.Policy.Project.Runtimes = c.rts
			files, err := rrsync.Render(context.Background(), in, all)
			if c.err != "" {
				assert.ErrorContains(t, err, c.err)
				return
			}
			require.NoError(t, err)
			var got []string
			for _, f := range files {
				got = append(got, f.Path)
			}
			assert.Equal(t, c.want, got)
		})
	}
}
