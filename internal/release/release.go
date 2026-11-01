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

// passEnv is the environment a release command gets besides PATH and a fresh HOME: no tokens.
var passEnv = []string{"TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TZ"}

// same rule as verify.safePath; dedup in wave 4
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func evalOr(p string) string {
	if e, err := filepath.EvalSymlinks(p); err == nil {
		return e
	}
	return p
}

// safePath is PATH reduced to absolute directories outside root.
// same rule as verify.safePath; dedup in wave 4
func safePath(root string) []string {
	evalRoot := evalOr(root)
	var dirs []string
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.IsAbs(d) && !within(evalRoot, evalOr(d)) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// run executes argv in root. The binary is found only in safePath; the environment
// is allowlisted with a throwaway HOME. A missing binary or a non-zero exit gives
// OK:false, never a panic.
func run(ctx context.Context, root string, argv []string) core.Check {
	name := strings.Join(argv, " ")
	dirs := safePath(root)
	bin := ""
	for _, d := range dirs {
		if fi, err := os.Stat(filepath.Join(d, argv[0])); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			bin = filepath.Join(d, argv[0])
			break
		}
	}
	if bin == "" {
		return core.Check{Name: name, Detail: argv[0] + " not found in the sanitized PATH"}
	}
	home, err := os.MkdirTemp("", "rr-release-home-")
	if err != nil {
		return core.Check{Name: name, Detail: err.Error()}
	}
	defer os.RemoveAll(home)
	c := exec.CommandContext(ctx, bin, argv[1:]...)
	c.Dir = root
	c.Env = []string{
		"PATH=" + strings.Join(dirs, string(filepath.ListSeparator)), "HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		// env beats the project .npmrc: no onload-script / node-options / global config from it
		"NPM_CONFIG_USERCONFIG=/dev/null", "NPM_CONFIG_GLOBALCONFIG=/dev/null",
		"NPM_CONFIG_ONLOAD_SCRIPT=", "NPM_CONFIG_NODE_OPTIONS=",
		"COMPOSER_HOME=" + filepath.Join(home, "composer"),
	}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err = c.Run()
	detail := strings.TrimSpace(buf.String())
	if len(detail) > 2000 {
		detail = detail[len(detail)-2000:]
	}
	if err != nil {
		return core.Check{Name: name, Detail: strings.TrimSpace(err.Error() + "\n" + detail)}
	}
	return core.Check{Name: name, OK: true, Detail: detail}
}

// step is one host check. ciOnly steps execute project code (build backend,
// Dockerfile RUN) and run only in the generated CI workflow. dist steps check
// an already built dist/ and fail if there is none.
type step struct {
	argv   []string
	ciOnly bool
	dist   bool
}

func (s step) run(ctx context.Context, root string) core.Check {
	name := strings.Join(s.argv, " ")
	if s.dist {
		name += " dist"
	}
	if s.ciOnly {
		return core.Check{Name: name, OK: true, Detail: "skipped: runs in CI (executes project code)"}
	}
	argv := s.argv
	if s.dist {
		if fi, err := os.Lstat(filepath.Join(root, "dist")); err == nil && !fi.IsDir() {
			return core.Check{Name: name, Detail: "dist is not a plain directory"}
		}
		files, _ := filepath.Glob(filepath.Join(root, "dist", "*"))
		if len(files) == 0 {
			return core.Check{Name: name, Detail: "no dist/: build runs in CI"}
		}
		argv = append(append([]string{}, argv...), files...)
	}
	c := run(ctx, root, argv)
	c.Name = name
	return c
}

func steps(cmds ...string) []step {
	out := make([]step, len(cmds))
	for i, c := range cmds {
		out[i] = step{argv: strings.Fields(c)}
	}
	return out
}

type adapter struct {
	name      string
	marker    string
	preflight []step
	dryRun    step
	bumpFile  string
	bump      func(content, version string) (string, error) // nil: the tag is the version
	workflow  core.File
}

func (a adapter) Name() string { return a.name }

func (a adapter) Detect(root string) bool {
	fi, err := os.Stat(filepath.Join(root, a.marker))
	return err == nil && fi.Mode().IsRegular()
}

func (a adapter) Preflight(ctx context.Context, root string) []core.Check {
	out := make([]core.Check, 0, len(a.preflight))
	for _, st := range a.preflight {
		out = append(out, st.run(ctx, root))
	}
	return out
}

func (a adapter) DryRun(ctx context.Context, root string) (core.Check, error) {
	return a.dryRun.run(ctx, root), nil
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

func (a adapter) CIWorkflow() core.File { return a.workflow }

// workflow reads the embedded template; init() may panic (AGENTS.md).
func workflow(name string) core.File {
	b, err := releasetpl.FS.ReadFile(name + ".yml")
	if err != nil {
		panic(err)
	}
	return core.File{Path: ".github/workflows/rr-release-" + name + ".yml", Content: b}
}

func replaceFirst(re *regexp.Regexp, content, repl string) (string, error) {
	loc := re.FindStringSubmatchIndex(content)
	if loc == nil {
		return "", errors.New("no version field found")
	}
	return content[:loc[2]] + repl + content[loc[3]:], nil
}

var (
	npmVersionRe = regexp.MustCompile(`(?m)^(?: {2}|\t)"version"\s*:\s*"([^"]*)"`) // top level only: indent depth 1
	pyVersionRe  = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]*)"`)
	pyProjectRe  = regexp.MustCompile(`(?m)^\[project\][ \t]*$`)
	pySectionRe  = regexp.MustCompile(`(?m)^\[`)
)

// bumpPy replaces version inside the [project] section only.
func bumpPy(c, v string) (string, error) {
	loc := pyProjectRe.FindStringIndex(c)
	if loc == nil {
		return "", errors.New("no [project] section")
	}
	start, end := loc[1], len(c)
	if n := pySectionRe.FindStringIndex(c[start:]); n != nil {
		end = start + n[0]
	}
	sec, err := replaceFirst(pyVersionRe, c[start:end], v)
	if err != nil {
		return "", err
	}
	return c[:start] + sec + c[end:], nil
}

func init() {
	Register(adapter{name: "composer", marker: "composer.json",
		workflow:  workflow("composer"),
		preflight: steps("composer validate --strict --no-plugins --no-scripts", "composer audit --no-plugins --no-scripts"),
		dryRun:    steps("composer validate --strict --no-plugins --no-scripts")[0]})
	Register(adapter{name: "npm", marker: "package.json", workflow: workflow("npm"),
		preflight: steps("npm pack --dry-run --ignore-scripts"),
		dryRun:    steps("npm publish --dry-run --ignore-scripts")[0], bumpFile: "package.json",
		bump: func(c, v string) (string, error) { return replaceFirst(npmVersionRe, c, v) }})
	twine := step{argv: []string{"twine", "check"}, dist: true}
	Register(adapter{name: "pypi", marker: "pyproject.toml", workflow: workflow("pypi"),
		preflight: []step{{argv: []string{"python", "-m", "build"}, ciOnly: true}, twine},
		dryRun:    twine, bumpFile: "pyproject.toml",
		bump: bumpPy})
	build := step{argv: []string{"docker", "build", "."}, ciOnly: true}
	Register(adapter{name: "docker", marker: "Dockerfile", workflow: workflow("docker"), preflight: []step{build}, dryRun: build})
}
