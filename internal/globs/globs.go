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
	"runtime"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// FoldCase makes matching case-insensitive. It defaults to true on hosts whose
// default filesystems are case-insensitive (macOS, Windows), so `.env` also
// protects `.ENV` there.
var FoldCase = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// Match reports whether rel (repo-relative, "/"-separated) matches pattern.
// An invalid pattern never matches; callers with deny semantics must also
// reject invalid patterns at load time (policy does).
func Match(pattern, rel string) bool {
	rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
	if FoldCase {
		pattern, rel = strings.ToLower(pattern), strings.ToLower(rel)
	}
	if ok, err := doublestar.Match(pattern, rel); err == nil && ok {
		return true
	}
	if strings.Contains(pattern, "/") {
		return false
	}
	ok, err := doublestar.Match(pattern, path.Base(rel))
	return err == nil && ok
}

// Valid reports whether pattern is syntactically valid and in a form Match can
// ever satisfy for repo-relative paths: no "./" prefix, no trailing "/", no
// empty pattern. Absolute ("/…") and home ("~/…") patterns are valid; callers
// match those against absolute paths.
func Valid(pattern string) bool {
	if pattern == "" || strings.HasPrefix(pattern, "./") || strings.HasSuffix(pattern, "/") {
		return false
	}
	return doublestar.ValidatePattern(pattern)
}
