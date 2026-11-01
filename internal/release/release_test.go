package release

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func write(t *testing.T, root, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
}

func TestDetect(t *testing.T) {
	root := t.TempDir()
	assert.Empty(t, Detected(root))
	write(t, root, "composer.json", "{}")
	write(t, root, "Dockerfile", "FROM scratch")
	var names []string
	for _, a := range Detected(root) {
		names = append(names, a.Name())
	}
	assert.Equal(t, []string{"composer", "docker"}, names)
}

func TestCIWorkflowGoldenAndNoCredentials(t *testing.T) {
	bad := regexp.MustCompile(`NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_API_TOKEN|PYPI_TOKEN|TWINE_|--provenance`)
	literal := regexp.MustCompile(`(^|\s)(password|token):`)
	secret := regexp.MustCompile(`secrets\.\w+`)
	for _, n := range []string{"composer", "npm", "pypi", "docker"} {
		a, _ := Get(n)
		f := a.CIWorkflow()
		assert.Equal(t, ".github/workflows/rr-release-"+n+".yml", f.Path)
		testutil.Golden(t, "workflow-"+n+".yml", f.Content)
		s := string(f.Content)
		assert.False(t, bad.MatchString(s), n)
		assert.Contains(t, s, "tags:")
		for _, m := range secret.FindAllString(s, -1) {
			assert.Equal(t, "secrets.GITHUB_TOKEN", m, n)
			assert.Equal(t, "docker", n)
		}
		for _, l := range strings.Split(s, "\n") {
			if literal.MatchString(l) {
				assert.Contains(t, l, "secrets.GITHUB_TOKEN", n)
			}
		}
	}
}

func TestPreflightFakeBins(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	a, _ := Get("npm")

	// missing binary: no panic, OK:false
	t.Setenv("PATH", t.TempDir())
	cs := a.Preflight(ctx, root)
	require.Len(t, cs, 1)
	assert.False(t, cs[0].OK)

	testutil.FakeBin(t, "npm", `echo "$@"`)
	cs = a.Preflight(ctx, root)
	require.Len(t, cs, 1)
	assert.True(t, cs[0].OK)
	assert.Equal(t, "pack --dry-run --ignore-scripts", cs[0].Detail)
	ch, _ := a.DryRun(ctx, root)
	assert.Equal(t, "publish --dry-run --ignore-scripts", ch.Detail)

	testutil.FakeBin(t, "npm", `echo "boom"; exit 3`)
	ch, err := a.DryRun(ctx, root)
	require.NoError(t, err)
	assert.False(t, ch.OK)
	assert.Contains(t, ch.Detail, "boom")
}

func TestPlantedBinaryNotRun(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "bin"), 0o755))
	marker := filepath.Join(root, "ran")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "bin", "composer"), []byte(script), 0o755))
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+"bin"+string(os.PathListSeparator)+t.TempDir())
	a, _ := Get("composer")
	for _, c := range a.Preflight(context.Background(), root) {
		assert.False(t, c.OK)
	}
	assert.NoFileExists(t, marker)
}

func TestNoProjectCodeOnHost(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	marker := filepath.Join(root, "ran")
	for _, bin := range []string{"python", "docker", "twine"} {
		testutil.FakeBin(t, bin, "touch "+marker)
	}
	py, _ := Get("pypi")
	cs := py.Preflight(ctx, root)
	require.Len(t, cs, 2)
	assert.Contains(t, cs[0].Detail, "runs in CI")
	assert.False(t, cs[1].OK) // no dist/
	assert.Contains(t, cs[1].Detail, "build runs in CI")
	ch, _ := py.DryRun(ctx, root)
	assert.False(t, ch.OK)
	dk, _ := Get("docker")
	ch, _ = dk.DryRun(ctx, root)
	assert.Contains(t, ch.Detail, "runs in CI")
	assert.NoFileExists(t, marker)

	// with a dist/, twine check runs on the existing files
	require.NoError(t, os.Mkdir(filepath.Join(root, "dist"), 0o755))
	write(t, root, "dist/x.whl", "")
	testutil.FakeBin(t, "twine", `echo "$@"`)
	ch, _ = py.DryRun(ctx, root)
	assert.True(t, ch.OK)
	assert.Equal(t, "twine check dist/*", ch.Name)
	assert.Contains(t, ch.Detail, "x.whl")
}

func TestWorkflowHardening(t *testing.T) {
	uses := regexp.MustCompile(`uses: \S+@[0-9a-f]{40}( |$)`)
	for _, n := range []string{"composer", "npm", "pypi", "docker"} {
		a, _ := Get(n)
		s := string(a.CIWorkflow().Content)
		for _, l := range strings.Split(s, "\n") {
			if strings.Contains(l, "uses:") {
				assert.Regexp(t, uses, l, n)
			}
			if strings.Contains(l, "ref_name") || strings.Contains(l, ".repository") {
				assert.Regexp(t, `^\s+(TAG|REPO):`, l, n) // never inside run:
			}
		}
		assert.Contains(t, s, "env:\n          TAG:", n)
	}
	for _, n := range []string{"npm", "pypi", "docker"} {
		a, _ := Get(n)
		assert.Contains(t, string(a.CIWorkflow().Content), "environment:", n)
	}
}

func TestEnvSanitized(t *testing.T) {
	for _, k := range []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "TWINE_PASSWORD", "GITHUB_TOKEN"} {
		t.Setenv(k, "leak")
	}
	testutil.FakeBin(t, "composer", `[ -z "$NPM_TOKEN$NODE_AUTH_TOKEN$TWINE_PASSWORD$GITHUB_TOKEN" ] || { echo leaked; exit 1; }`)
	a, _ := Get("composer")
	for _, c := range a.Preflight(context.Background(), t.TempDir()) {
		assert.True(t, c.OK, c.Detail)
	}
}

func TestPrepareTag(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	write(t, root, "package.json", "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\"version\": \"9\"}\n}\n")
	write(t, root, "pyproject.toml", "[project]\nname = \"x\"\nversion = \"0.1.0\"\n")

	npm, _ := Get("npm")
	fs, err := npm.PrepareTag(ctx, root, "1.2.3")
	require.NoError(t, err)
	require.Len(t, fs, 1)
	assert.Equal(t, "package.json", fs[0].Path)
	assert.Contains(t, string(fs[0].Content), `"version": "1.2.3"`)
	assert.Contains(t, string(fs[0].Content), `{"version": "9"}`)
	b, _ := os.ReadFile(filepath.Join(root, "package.json"))
	assert.Contains(t, string(b), "1.0.0") // not written

	py, _ := Get("pypi")
	fs, err = py.PrepareTag(ctx, root, "2.0.0-rc.1")
	require.NoError(t, err)
	assert.Contains(t, string(fs[0].Content), `version = "2.0.0-rc.1"`)

	// an earlier/nested version must not be touched
	write(t, root, "package.json", "{\n  \"dependencies\": {\n    \"version\": \"9\"\n  },\n  \"version\": \"1.0.0\"\n}\n")
	fs, err = npm.PrepareTag(ctx, root, "1.5.0")
	require.NoError(t, err)
	assert.Contains(t, string(fs[0].Content), `"version": "9"`)
	assert.Contains(t, string(fs[0].Content), `"version": "1.5.0"`)
	write(t, root, "pyproject.toml", "[tool.x]\nversion = \"9\"\n[project]\nname = \"x\"\nversion = \"0.1.0\"\n[tool.y]\nversion = \"8\"\n")
	fs, err = py.PrepareTag(ctx, root, "0.2.0")
	require.NoError(t, err)
	assert.Equal(t, "[tool.x]\nversion = \"9\"\n[project]\nname = \"x\"\nversion = \"0.2.0\"\n[tool.y]\nversion = \"8\"\n", string(fs[0].Content))
	write(t, root, "pyproject.toml", "[tool.x]\nversion = \"9\"\n[project]\nname = \"x\"\n")
	_, err = py.PrepareTag(ctx, root, "0.2.0")
	assert.Error(t, err)

	for _, eco := range []string{"composer", "docker"} {
		a, _ := Get(eco)
		fs, err = a.PrepareTag(ctx, root, "1.0.0")
		require.NoError(t, err)
		assert.Empty(t, fs)
	}
	for _, v := range []string{"v1.2.3", "1.2", "x", "", "01.2.3"} {
		_, err = npm.PrepareTag(ctx, root, v)
		assert.Error(t, err, v)
	}
	_, err = npm.PrepareTag(ctx, t.TempDir(), "1.0.0")
	assert.Error(t, err)
	write(t, root, "package.json", "{}")
	_, err = npm.PrepareTag(ctx, root, "1.0.0")
	assert.Error(t, err)
}

func TestCheckChangelog(t *testing.T) {
	const doc = "# Changelog\n\n## [Unreleased]\n\n### Added\n- thing\n\n## [1.0.0] - 2026-01-01\n### Fixed\n\n## [0.9.0]\n- x\n\n[Unreleased]: https://x/compare\n"
	cases := []struct {
		name, body, version string
		ok                  bool
	}{
		{"unreleased", doc, "", true},
		{"version empty", doc, "1.0.0", false},
		{"version ok", doc, "0.9.0", true},
		{"missing", doc, "3.0.0", false},
		{"unreleased only heading", "## [Unreleased]\n\n### Added\n\n## [1.0.0]\n- a\n", "", false},
		{"link refs are not content", "## [Unreleased]\n\n[Unreleased]: https://x\n", "", false},
		{"comment is not content", "## [Unreleased]\n<!-- todo -->\n", "", false},
		{"plain heading", "## Unreleased\n- a\n", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "CHANGELOG.md", c.body)
			err := CheckChangelog(root, c.version)
			assert.Equal(t, c.ok, err == nil, "%v", err)
		})
	}
	assert.Error(t, CheckChangelog(t.TempDir(), ""))
}
