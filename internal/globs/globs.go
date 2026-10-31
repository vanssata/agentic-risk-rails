// Package globs is the single path-pattern matcher shared by policy (LOOSEN
// detection over file sets) and guard (enforcement). Both MUST use it so that
// what the differ compares is exactly what the guard enforces.
//
// Semantics: doublestar/v4 (`*` stops at "/", `**` crosses it) on clean,
// slash-separated repo-relative paths, plus gitignore-style depth: a pattern
// without "/" (e.g. ".env*", "riskrails.yaml") matches the base name at any
// depth. Matching is case-insensitive on the base name for patterns without
// "/" only if FoldCase is set (macOS/Windows hosts).
package globs

import (
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// FoldCase makes slash-less patterns case-insensitive (set on case-insensitive hosts).
var FoldCase = false

// Match reports whether rel (repo-relative, "/"-separated) matches pattern.
// An invalid pattern never matches; callers with deny semantics must also
// reject invalid patterns at load time (policy does).
func Match(pattern, rel string) bool {
	rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
	if ok, err := doublestar.Match(pattern, rel); err == nil && ok {
		return true
	}
	if strings.Contains(pattern, "/") {
		return false
	}
	base := path.Base(rel)
	if FoldCase {
		pattern, base = strings.ToLower(pattern), strings.ToLower(base)
	}
	ok, err := doublestar.Match(pattern, base)
	return err == nil && ok
}

// Valid reports whether pattern is syntactically valid.
func Valid(pattern string) bool { return doublestar.ValidatePattern(pattern) }
