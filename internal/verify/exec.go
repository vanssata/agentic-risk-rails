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

// hostCmd builds argv for root with the allowlisted environment. A bare command
// name is looked up in safePath only (exec would use the process PATH); a name
// with a slash (vendor/bin/phpunit) is the project's own and is relative to root.
func hostCmd(ctx context.Context, root string, argv ...string) (*exec.Cmd, error) {
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
