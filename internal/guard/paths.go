package guard

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

const policyFile = "riskrails.yaml"

// target is a resolved path: abs is symlink-resolved; rel is relative to the
// (symlink-resolved) root and only meaningful when inside.
type target struct {
	abs    string
	rel    string
	inside bool
}

// resolve expands ~, anchors relative paths at cwd (or root), resolves symlinks
// of the longest existing prefix and relates the result to the repo root.
func resolve(p, cwd string, gc core.GuardContext) target {
	switch {
	case p == "~":
		p = gc.Home
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(gc.Home, p[2:])
	}
	if !filepath.IsAbs(p) {
		base := gc.Root
		if filepath.IsAbs(cwd) {
			base = cwd
		}
		p = filepath.Join(base, p)
	}
	abs := evalPrefix(filepath.Clean(p))
	root := evalPrefix(filepath.Clean(gc.Root))
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return target{abs: abs}
	}
	return target{abs: abs, rel: filepath.ToSlash(rel), inside: true}
}

// evalPrefix resolves symlinks of the longest existing prefix of p, following
// dangling links by hand (writing through one creates its target).
func evalPrefix(p string) string {
	for hops := 0; hops < 40; hops++ {
		rest := ""
		cur := p
		for {
			if r, err := filepath.EvalSymlinks(cur); err == nil {
				return filepath.Join(r, rest)
			}
			if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				dest, err := os.Readlink(cur)
				if err != nil {
					return p
				}
				if !filepath.IsAbs(dest) {
					dest = filepath.Join(filepath.Dir(cur), dest)
				}
				p = filepath.Join(dest, rest)
				break
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				return p
			}
			rest = filepath.Join(filepath.Base(cur), rest)
			cur = parent
		}
	}
	return p
}

// expandRefs replaces "$name" entries by the referenced policy list.
func expandRefs(list []string, e core.EnforcementSpec) []string {
	var out []string
	for _, s := range list {
		switch s {
		case "$secret_reads":
			out = append(out, e.SecretReads...)
		case "$protected_paths":
			out = append(out, e.ProtectedPaths...)
		default:
			if !strings.HasPrefix(s, "$") {
				out = append(out, s)
			}
		}
	}
	return out
}

// matchesRule reports the first pattern of list matching t.
func matchesRule(list []string, t target, gc core.GuardContext) (string, bool) {
	for _, pat := range list {
		switch {
		case pat == "~" || strings.HasPrefix(pat, "~/"):
			if matchPath(quoteMeta(filepath.ToSlash(gc.Home))+strings.TrimPrefix(pat, "~"), filepath.ToSlash(t.abs)) {
				return pat, true
			}
		case filepath.IsAbs(pat):
			if matchPath(filepath.ToSlash(pat), filepath.ToSlash(t.abs)) {
				return pat, true
			}
		case t.inside && matchPath(pat, t.rel):
			return pat, true
		}
	}
	return "", false
}

func isPolicyFile(t target) bool {
	return t.inside && strings.EqualFold(t.rel, policyFile)
}

var ignoredDevices = map[string]bool{"/dev/null": true, "/dev/stdout": true, "/dev/stderr": true, "/dev/stdin": true, "/dev/tty": true, "/dev/zero": true}

// checkPath applies the path rules to one path. viaShell marks paths found in
// a Bash command: those can never edit riskrails.yaml (no diff is possible).
func checkPath(p string, write bool, call core.ToolCall, gc core.GuardContext, viaShell bool) core.Verdict {
	if ignoredDevices[p] || strings.HasPrefix(p, "/dev/fd/") {
		return core.Verdict{Decision: core.Allow}
	}
	e := gc.Policy.Policy.Enforcement
	t := resolve(p, call.Cwd, gc)
	if !write {
		list := append(append([]string{}, e.SecretReads...), expandRefs(e.Sandbox.NoRead, e)...)
		if pat, ok := matchesRule(list, t, gc); ok {
			return core.Verdict{Decision: core.Deny, Reason: "read of secret path " + p, Rule: "enforcement.secret_reads: " + pat}
		}
		return core.Verdict{Decision: core.Allow}
	}
	if viaShell && isPolicyFile(t) {
		return core.Verdict{Decision: core.Deny, Reason: policyFile + " may only change through an Edit/Write that is policy-diffed", Rule: "enforcement.protected_paths: " + policyFile}
	}
	list := append(append(append([]string{}, e.ProtectedPaths...), expandRefs(e.Sandbox.Readonly, e)...), expandRefs(e.Sandbox.NoWrite, e)...)
	if pat, ok := matchesRule(list, t, gc); ok {
		return core.Verdict{Decision: core.Deny, Reason: "write to protected path " + p, Rule: "enforcement.protected_paths: " + pat}
	}
	if !t.inside {
		return core.Verdict{Decision: askOrDeny(gc), Reason: "write outside the repository: " + p, Rule: "enforcement.sandbox.outside_root"}
	}
	if gc.StepFiles != nil && !inStepFiles(gc.StepFiles, t.rel, gc) {
		return core.Verdict{Decision: core.Deny, Reason: "scope guard: " + t.rel + " is not a file of the current step", Rule: "scope_guard"}
	}
	return core.Verdict{Decision: core.Allow}
}

func inStepFiles(files []string, rel string, gc core.GuardContext) bool {
	for _, f := range files {
		if filepath.IsAbs(f) {
			if r, err := filepath.Rel(gc.Root, f); err == nil {
				f = r
			}
		}
		if filepath.ToSlash(filepath.Clean(f)) == rel {
			return true
		}
	}
	return false
}

// globTargets expands a path that contains unquoted wildcards (cat .env*).
func globTargets(p string, cwd string, gc core.GuardContext) []string {
	pat := p
	if strings.HasPrefix(p, "~/") {
		pat = filepath.Join(gc.Home, p[2:])
	} else if !filepath.IsAbs(p) {
		base := gc.Root
		if filepath.IsAbs(cwd) {
			base = cwd
		}
		pat = filepath.Join(base, p)
	}
	m, err := filepath.Glob(pat)
	if err != nil || len(m) > 200 {
		return []string{p}
	}
	m = append(m, pat)
	return m
}

// quoteMeta escapes glob metacharacters of a literal path prefix (home dirs may contain braces).
func quoteMeta(s string) string {
	var sb strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`\*?[]{}`, c) {
			sb.WriteByte('\\')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
