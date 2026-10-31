package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// runCmd executes spec.Cmd (whitespace-split, no shell) plus extra and tests in
// root. Exit 0 is a pass; a non-zero exit is a failed TestResult, not an error.
// A non-full call without tests runs nothing and is Passed=false (no fake green).
func runCmd(ctx context.Context, root string, spec core.VerifyAdapterSpec, tests []string, full bool, extra ...string) (core.TestResult, error) {
	argv := strings.Fields(spec.Cmd)
	if len(argv) == 0 {
		return core.TestResult{}, fmt.Errorf("verify: adapter %q has no cmd", spec.Name)
	}
	for _, t := range tests {
		if strings.HasPrefix(t, "-") {
			return core.TestResult{}, fmt.Errorf("verify: refusing test path %q: it would be read as an option", t)
		}
	}
	if !full {
		if len(tests) == 0 {
			return core.TestResult{Output: "no tests selected"}, nil
		}
		argv = append(argv, extra...)
		argv = append(argv, tests...)
	}
	var out bytes.Buffer
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	c.Dir, c.Stdout, c.Stderr = root, &out, &out
	start := time.Now()
	err := c.Run()
	res := core.TestResult{Output: out.String(), Duration: time.Since(start)}
	if !full {
		res.Ran = tests
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		res.Passed = true
	case errors.As(err, &ee):
		if !full {
			res.Failed = tests // coarse: per-test attribution needs a runner-specific report
		}
	default:
		return res, fmt.Errorf("verify: %s: %w", spec.Name, err)
	}
	return res, nil
}
