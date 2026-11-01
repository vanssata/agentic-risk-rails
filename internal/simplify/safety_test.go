package simplify

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestFlagLikeFilesDropped(t *testing.T) {
	dir := repo(t)
	t.Setenv("PATH", t.TempDir())
	r := Run(context.Background(), dir, []string{"-x", "--config=evil", "a.go"})
	assert.Equal(t, []string{"a.go"}, r.Files)
}

func TestAstGrepArgsAndEnv(t *testing.T) {
	t.Setenv("RR_SECRET", "hidden")
	out := filepath.Join(t.TempDir(), "argv")
	testutil.FakeBin(t, "ast-grep", `echo "$@" > `+out+`; env >> `+out)
	rep := astGrep(context.Background(), repo(t), []string{"a.go"})
	assert.Equal(t, "ok", rep.Status)
	b, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(b), "scan --json=stream -- a.go")
	assert.NotContains(t, string(b), "RR_SECRET")
}

func TestBinaryInsideRootIgnored(t *testing.T) {
	dir := repo(t)
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "ast-grep"), []byte("#!/bin/sh\necho x\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+"relative")
	assert.Equal(t, "skipped: not installed", astGrep(context.Background(), dir, []string{"a.go"}).Status)
}

func TestCustomLanguagesSkipped(t *testing.T) {
	testutil.FakeBin(t, "ast-grep", "exit 0")
	dir := testutil.GitRepo(t, map[string]string{"a.go": "package a\n", "sgconfig.yml": "customLanguages:\n  x:\n    libraryPath: l.so\n"})
	assert.Equal(t, "skipped: custom languages load code", astGrep(context.Background(), dir, []string{"a.go"}).Status)
}
