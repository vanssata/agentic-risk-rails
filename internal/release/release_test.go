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

	// missing binary: no panic, OK:false (sh finds nothing named npm)
	t.Setenv("PATH", "/usr/bin:/bin")
	if _, err := os.Stat("/usr/bin/npm"); err != nil {
		cs := a.Preflight(ctx, root)
		require.Len(t, cs, 1)
		assert.False(t, cs[0].OK)
	}

	testutil.FakeBin(t, "npm", `echo "packed"`)
	cs := a.Preflight(ctx, root)
	require.Len(t, cs, 1)
	assert.True(t, cs[0].OK)
	assert.Equal(t, "packed", cs[0].Detail)

	testutil.FakeBin(t, "npm", `echo "boom"; exit 3`)
	ch, err := a.DryRun(ctx, root)
	require.NoError(t, err)
	assert.False(t, ch.OK)
	assert.Contains(t, ch.Detail, "boom")
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
