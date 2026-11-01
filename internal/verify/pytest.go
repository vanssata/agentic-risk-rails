package verify

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Pytest selects tests from a static import graph (testmon is not required):
// every test file that transitively imports a changed module. Imports are read
// by regex, so dynamic imports are invisible (selection_misses catches those).
type Pytest struct{}

func (Pytest) Name() string { return "pytest" }

func (Pytest) Detect(root string) bool {
	return exists(root, "pytest.ini") || exists(root, "conftest.py") || exists(root, "pyproject.toml") || exists(root, "setup.cfg") || exists(root, "tox.ini")
}

var (
	pyImport = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([\w., \t]+)`)
	pyFrom   = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+\(?([\w, \t]+)`)
)

func isPyTest(rel string) bool {
	b := path.Base(rel)
	return strings.HasSuffix(b, ".py") && (strings.HasPrefix(b, "test_") || strings.HasSuffix(b, "_test.py"))
}

// pyModule is the dotted name of a file, ignoring a leading src/.
func pyModule(rel string) string {
	m := strings.TrimSuffix(strings.TrimPrefix(rel, "src/"), ".py")
	m = strings.TrimSuffix(m, "/__init__")
	return strings.ReplaceAll(m, "/", ".")
}

// pyImports returns the dotted names a source may refer to.
func pyImports(src string) []string {
	var out []string
	for _, m := range pyImport.FindAllStringSubmatch(src, -1) {
		for _, p := range strings.Split(m[1], ",") {
			if f := strings.Fields(p); len(f) > 0 {
				out = append(out, f[0])
			}
		}
	}
	for _, m := range pyFrom.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
		for _, p := range strings.Split(m[2], ",") {
			if f := strings.Fields(p); len(f) > 0 {
				out = append(out, m[1]+"."+f[0])
			}
		}
	}
	return out
}

func (Pytest) Map(_ context.Context, root string, changed []string) (tests, uncovered []string, err error) {
	files, err := walkFiles(root, func(rel string) bool { return strings.HasSuffix(rel, ".py") })
	if err != nil {
		return nil, nil, err
	}
	byMod := map[string]string{}
	for _, f := range files {
		byMod[pyModule(f)] = f
	}
	rdeps := map[string][]string{} // file -> files importing it
	for _, f := range files {
		src, err := readFile(root, f)
		if err != nil {
			return nil, nil, err
		}
		for _, imp := range pyImports(src) {
			if t, ok := byMod[imp]; ok && t != f {
				rdeps[t] = append(rdeps[t], f)
			}
		}
	}
	for _, c := range changed {
		if !strings.HasSuffix(c, ".py") {
			uncovered = append(uncovered, c)
			continue
		}
		seen, queue, found := map[string]bool{c: true}, []string{c}, false
		for len(queue) > 0 {
			f := queue[0]
			queue = queue[1:]
			if isPyTest(f) {
				tests, found = append(tests, f), true
			}
			for _, d := range rdeps[f] {
				if !seen[d] {
					seen[d] = true
					queue = append(queue, d)
				}
			}
		}
		if !found {
			uncovered = append(uncovered, c)
		}
	}
	return uniq(tests), uniq(uncovered), nil
}

func (Pytest) Run(ctx context.Context, root string, spec core.VerifyAdapterSpec, tests []string, full bool) (core.TestResult, error) {
	return runCmd(ctx, root, spec, tests, full)
}
