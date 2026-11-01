package verify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/hostexec"
)

// passEnv is the whole environment an adapter process gets, besides PATH. Nothing
// that configures the tools themselves (GO*, PYTEST_ADDOPTS, NODE_OPTIONS,
// PHPUNIT*, *_OPTIONS, *FLAGS, ...) is passed on.
var passEnv = []string{"HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TZ", "SYSTEMROOT"}

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

type sandboxKey struct{}

// Sandbox rewrites an adapter argv into the argv of a sandboxed run of it
// (e.g. `docker run ... <argv>` for the runner's close run, errata #26). The
// result's first element is looked up like any bare command name.
type Sandbox func(argv []string) ([]string, error)

// WithSandbox makes every adapter command started with ctx (map and run) go
// through sb instead of running on the host.
func WithSandbox(ctx context.Context, sb Sandbox) context.Context {
	return context.WithValue(ctx, sandboxKey{}, sb)
}

// hostCmd builds argv for root with the allowlisted environment. A bare command
// name is looked up in safePath only (exec would use the process PATH); a name
// with a slash (vendor/bin/phpunit) is the project's own and is relative to root.
// Under WithSandbox the argv is first rewritten by the sandbox.
func hostCmd(ctx context.Context, root string, argv ...string) (*exec.Cmd, error) {
	if sb, ok := ctx.Value(sandboxKey{}).(Sandbox); ok {
		wrapped, err := sb(argv)
		if err != nil {
			return nil, fmt.Errorf("verify: sandbox: %w", err)
		}
		if len(wrapped) == 0 || strings.Contains(wrapped[0], "/") {
			return nil, fmt.Errorf("verify: sandbox must return a bare command name, got %q", wrapped)
		}
		argv = wrapped
	}
	dirs := hostexec.SafePath(root)
	name := argv[0]
	if !strings.Contains(name, "/") {
		found, ok := hostexec.Lookup(dirs, name)
		if !ok {
			return nil, fmt.Errorf("verify: %q not found in the sanitized PATH", name)
		}
		name = found
	}
	c := exec.CommandContext(ctx, name, argv[1:]...)
	c.Dir = root
	c.Env = []string{"PATH=" + strings.Join(dirs, string(filepath.ListSeparator))}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	return c, nil
}
