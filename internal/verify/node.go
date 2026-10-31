package verify

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Node drives jest or vitest. jest: the related tests are listed with
// `jest --listTests --findRelatedTests <file>`, one call per file so a file with
// no related test is reported uncovered. vitest has no verified listing mode, so
// Map returns the changed source files as the selector and Run executes
// `vitest related --run <files>`; an uncovered file then shows up only as a
// failed (no tests found) run or, later, as a selection miss.
type Node struct{ Tool string } // "jest" | "vitest"

func (n Node) Name() string { return n.Tool }

func (n Node) Detect(root string) bool {
	return exists(root, "package.json") && strings.Contains(readFile(root, "package.json"), `"`+n.Tool+`"`)
}

var nodeTestFile = regexp.MustCompile(`\.(test|spec)\.[cm]?[jt]sx?$`)

func (n Node) Map(ctx context.Context, root string, changed []string) (tests, uncovered []string, err error) {
	for _, f := range changed {
		if strings.HasPrefix(f, "-") {
			return nil, nil, fmt.Errorf("verify: refusing path %q: it would be read as an option", f)
		}
		switch {
		case nodeTestFile.MatchString(f):
			tests = append(tests, f)
		case n.Tool == "vitest":
			tests = append(tests, f)
		default:
			var out bytes.Buffer
			c := exec.CommandContext(ctx, "npx", "--no-install", "jest", "--listTests", "--findRelatedTests", f)
			c.Dir, c.Stdout = root, &out
			if err := c.Run(); err != nil {
				return nil, nil, fmt.Errorf("verify: jest --listTests: %w", err)
			}
			n0 := len(tests)
			for _, l := range strings.Fields(out.String()) {
				if rel, err := filepath.Rel(root, l); err == nil {
					tests = append(tests, filepath.ToSlash(rel))
				}
			}
			if len(tests) == n0 {
				uncovered = append(uncovered, f)
			}
		}
	}
	return uniq(tests), uniq(uncovered), nil
}

func (n Node) Run(ctx context.Context, root string, spec core.VerifyAdapterSpec, tests []string, full bool) (core.TestResult, error) {
	if n.Tool == "vitest" {
		return runCmd(ctx, root, spec, tests, full, "related", "--run")
	}
	return runCmd(ctx, root, spec, tests, full)
}
