package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestChangelogCheckCmd(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "CHANGELOG.md"), []byte("## [Unreleased]\n- a\n## [1.0.0]\n"), 0o644))
	_, err := runPolicyRR(t, "changelog", "--check", "--root", root)
	assert.NoError(t, err)
	_, err = runPolicyRR(t, "changelog", "--check", "--root", root, "--version", "1.0.0")
	assert.Error(t, err)
}

func TestReleaseCmd(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte("{\n  \"version\": \"1.0.0\"\n}\n"), 0o644))
	testutil.FakeBin(t, "npm", "exit 0")
	_, err := runPolicyRR(t, "release", "preflight", "--root", root)
	assert.NoError(t, err)
	_, err = runPolicyRR(t, "release", "prepare", "bad", "--root", root)
	assert.Error(t, err)
	_, err = runPolicyRR(t, "release", "prepare", "1.1.0", "--root", root)
	require.NoError(t, err)
	b, _ := os.ReadFile(filepath.Join(root, "package.json"))
	assert.Contains(t, string(b), `"1.1.0"`)
	_, err = runPolicyRR(t, "release", "workflow", "--root", root)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(root, ".github/workflows/rr-release-npm.yml"))
}
