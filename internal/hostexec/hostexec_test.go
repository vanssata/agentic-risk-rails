package hostexec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafePathDropsRootAndRelative(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	other := t.TempDir()
	require.NoError(t, os.Mkdir(bin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "tool"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(other, "tool"), []byte("#!/bin/sh\n"), 0o755))
	sep := string(os.PathListSeparator)
	t.Setenv("PATH", bin+sep+"relative"+sep+root+sep+other)

	dirs := SafePath(root)
	assert.Equal(t, []string{other}, dirs)
	p, ok := Lookup(dirs, "tool")
	assert.True(t, ok)
	assert.Equal(t, filepath.Join(other, "tool"), p)
	_, ok = Lookup(nil, "tool")
	assert.False(t, ok)
}
