// Package release holds the release adapters (DES §9.1). Adapters never publish:
// CI publishes on tag (OIDC / webhook / GITHUB_TOKEN); nothing here holds credentials.
package release

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	releasetpl "github.com/vanssata/agentic-risk-rails/templates/release"
)

var registry = map[string]core.ReleaseAdapter{}

// Register adds an adapter; the name must be unique.
func Register(a core.ReleaseAdapter) {
	if _, dup := registry[a.Name()]; dup {
		panic("release: duplicate adapter " + a.Name())
	}
	registry[a.Name()] = a
}

// Get returns the adapter registered under name.
func Get(name string) (core.ReleaseAdapter, bool) { a, ok := registry[name]; return a, ok }

// Detected returns the adapters whose Detect(root) is true, by name.
func Detected(root string) []core.ReleaseAdapter {
	var out []core.ReleaseAdapter
	for _, a := range registry {
		if a.Detect(root) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// ValidVersion reports whether v is semver without a "v" prefix.
func ValidVersion(v string) error {
	if !semverRe.MatchString(v) {
		return fmt.Errorf("release: %q is not a semver version (x.y.z)", v)
	}
	return nil
}

// passEnv is the whole environment a release command gets besides PATH: no tokens.
var passEnv = []string{"HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TZ"}

// sh runs a constant command line in root with the allowlisted environment.
// A missing binary or non-zero exit gives OK:false, never a panic.
func sh(ctx context.Context, root, line string) core.Check {
	c := exec.CommandContext(ctx, "sh", "-c", line)
	c.Dir = root
	c.Env = []string{"PATH=" + os.Getenv("PATH")}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	detail := strings.TrimSpace(buf.String())
	if len(detail) > 2000 {
		detail = detail[len(detail)-2000:]
	}
	if err != nil {
		return core.Check{Name: line, Detail: strings.TrimSpace(err.Error() + "\n" + detail)}
	}
	return core.Check{Name: line, OK: true, Detail: detail}
}

type adapter struct {
	name      string
	marker    string
	preflight []string
	dryRun    string
	bumpFile  string
	bump      func(content, version string) (string, error) // nil: the tag is the version
}

func (a adapter) Name() string { return a.name }

func (a adapter) Detect(root string) bool {
	fi, err := os.Stat(filepath.Join(root, a.marker))
	return err == nil && fi.Mode().IsRegular()
}

func (a adapter) Preflight(ctx context.Context, root string) []core.Check {
	out := make([]core.Check, 0, len(a.preflight))
	for _, l := range a.preflight {
		out = append(out, sh(ctx, root, l))
	}
	return out
}

func (a adapter) DryRun(ctx context.Context, root string) (core.Check, error) {
	return sh(ctx, root, a.dryRun), nil
}

// PrepareTag returns the files to change for version; it writes nothing.
func (a adapter) PrepareTag(_ context.Context, root, version string) ([]core.File, error) {
	if err := ValidVersion(version); err != nil {
		return nil, err
	}
	if a.bump == nil {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(root, a.bumpFile))
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	s, err := a.bump(string(b), version)
	if err != nil {
		return nil, fmt.Errorf("release: %s: %w", a.bumpFile, err)
	}
	return []core.File{{Path: a.bumpFile, Content: []byte(s)}}, nil
}

func (a adapter) CIWorkflow() core.File {
	b, err := releasetpl.FS.ReadFile(a.name + ".yml")
	if err != nil { // embedded at build time: cannot happen
		panic(err)
	}
	return core.File{Path: ".github/workflows/rr-release-" + a.name + ".yml", Content: b}
}

func replaceFirst(re *regexp.Regexp, content, repl string) (string, error) {
	loc := re.FindStringSubmatchIndex(content)
	if loc == nil {
		return "", errors.New("no version field found")
	}
	return content[:loc[2]] + repl + content[loc[3]:], nil
}

var (
	npmVersionRe = regexp.MustCompile(`(?m)^\s*"version"\s*:\s*"([^"]*)"`)
	pyVersionRe  = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]*)"`)
)

func init() {
	Register(adapter{name: "composer", marker: "composer.json",
		preflight: []string{"composer validate --strict", "composer audit"},
		dryRun:    "composer validate --strict"})
	Register(adapter{name: "npm", marker: "package.json",
		preflight: []string{"npm pack --dry-run"},
		dryRun:    "npm publish --dry-run", bumpFile: "package.json",
		bump: func(c, v string) (string, error) { return replaceFirst(npmVersionRe, c, v) }})
	Register(adapter{name: "pypi", marker: "pyproject.toml",
		preflight: []string{"python -m build", "twine check dist/*"},
		dryRun:    "python -m build && twine check dist/*", bumpFile: "pyproject.toml",
		bump: func(c, v string) (string, error) { return replaceFirst(pyVersionRe, c, v) }})
	Register(adapter{name: "docker", marker: "Dockerfile",
		preflight: []string{"docker build ."},
		dryRun:    "docker build ."})
}
