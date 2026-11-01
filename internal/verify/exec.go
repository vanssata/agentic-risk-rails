package verify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// safePath is the PATH of the rr process reduced to absolute directories outside
// root: a binary planted in the repository (or a relative entry) is never found.
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

// hostCmd builds argv for root with the allowlisted environment. A bare command
// name is looked up in safePath only (exec would use the process PATH); a name
// with a slash (vendor/bin/phpunit) is the project's own and is relative to root.
func hostCmd(ctx context.Context, root string, argv ...string) (*exec.Cmd, error) {
	dirs := safePath(root)
	name := argv[0]
	if !strings.Contains(name, "/") {
		found := ""
		for _, d := range dirs {
			if fi, err := os.Stat(filepath.Join(d, name)); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
				found = filepath.Join(d, name)
				break
			}
		}
		if found == "" {
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
