// Package hostexec holds the PATH rule shared by every module that runs
// project-selected tools outside the agent sandbox.
package hostexec

import (
	"os"
	"path/filepath"
	"strings"
)

// SafePath is the PATH of the rr process reduced to absolute directories
// outside root: a binary planted in the repository (or a relative entry) is
// never found.
func SafePath(root string) []string {
	evalRoot := EvalOr(root)
	var dirs []string
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.IsAbs(d) && !Within(evalRoot, EvalOr(d)) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// Within reports whether p is root or below it.
func Within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// EvalOr resolves symlinks in p, or returns p when it cannot.
func EvalOr(p string) string {
	if e, err := filepath.EvalSymlinks(p); err == nil {
		return e
	}
	return p
}

// Lookup finds an executable regular file name in dirs.
func Lookup(dirs []string, name string) (string, bool) {
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}
