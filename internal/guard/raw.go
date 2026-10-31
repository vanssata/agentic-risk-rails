package guard

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Tools the guard does not know (MCP, future runtime tools) and Grep/Glob are
// judged from the raw tool input: the adapter only fills ToolCall.Paths for
// tools it knows. Every string value is examined whatever its key; keys only
// hint at the role (shell text, model).

var (
	rawCmdKeys   = opts("command", "cmd", "script", "code", "shell", "sh")
	camelRe      = regexp.MustCompile(`[A-Z]?[a-z0-9]+|[A-Z]+`)
	writeVerbs   = opts("write", "create", "edit", "delete", "remove", "move", "rename", "put", "upload", "patch", "append", "save", "update", "mkdir", "touch", "copy", "replace", "insert", "apply", "push", "publish", "send", "set")
	rawMetaKeys  = opts("cwd", "transcriptpath", "sessionid", "hookeventname", "toolname", "permissionmode", "toolusid", "tooluseid")
	urlSlashesRe = regexp.MustCompile(`^//[A-Za-z0-9.-]+`)
)

// rawVal is one string found in the raw input with the (normalised) key above it.
type rawVal struct{ key, s string }

// scanRaw returns every string value, with its key (lower case, no _ or -).
func scanRaw(raw json.RawMessage) []rawVal {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var out []rawVal
	var walk func(v any, key string, depth int)
	walk = func(v any, key string, depth int) {
		if depth > 8 || len(out) > 500 {
			return
		}
		switch x := v.(type) {
		case string:
			out = append(out, rawVal{key, x})
		case []any:
			for _, e := range x {
				walk(e, key, depth+1)
			}
		case map[string]any:
			for k, e := range x {
				nk := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k))
				if depth == 0 && rawMetaKeys[nk] {
					continue
				}
				walk(e, nk, depth+1)
			}
		}
	}
	walk(v, "", 0)
	return out
}

func rawByKey(vals []rawVal, key string) []string {
	var out []string
	for _, v := range vals {
		if v.key == key {
			out = append(out, v.s)
		}
	}
	return out
}

func writeLike(tool string) bool {
	for _, tok := range camelRe.FindAllString(tool, -1) {
		if writeVerbs[strings.ToLower(tok)] {
			return true
		}
	}
	return false
}

func urlLikeValue(s string) bool {
	return schemeRe.MatchString(s) || urlSlashesRe.MatchString(s)
}

// checkUnknownTool applies the path, egress, shell and model rules to every
// value a tool carries in its raw input.
func checkUnknownTool(call core.ToolCall, gc core.GuardContext) core.Verdict {
	var r result
	e := gc.Policy.Policy.Enforcement
	var vals []rawVal
	if call.Command == "" && !strings.EqualFold(call.Tool, "bash") {
		vals = scanRaw(call.Raw)
	}
	paths := append([]string{}, call.Paths...)
	var urls, cmds, models []string
	for _, v := range vals {
		switch {
		case rawCmdKeys[v.key]:
			cmds = append(cmds, v.s)
		case v.key == "model":
			models = append(models, v.s)
		case urlLikeValue(v.s):
			urls = append(urls, strings.TrimPrefix(v.s, "//"))
			if strings.HasPrefix(v.s, "//") {
				urls[len(urls)-1] = "http://" + urls[len(urls)-1]
			}
		case pathLike(v.s, call, gc):
			paths = append(paths, v.s)
		}
	}
	if call.URL != "" {
		urls = append(urls, call.URL)
	}
	if call.Command != "" || strings.EqualFold(call.Tool, "bash") {
		r.add(checkBash(call, gc))
	}
	write := writeLike(call.Tool)
	for _, p := range paths {
		if write {
			r.add(checkPath(p, true, call, gc, false))
			r.add(checkPath(p, false, call, gc, false))
		} else {
			r.add(checkEither(p, call, gc, false))
		}
		r.add(checkDir(p, call, gc))
	}
	for _, u := range urls {
		r.add(checkHost(hostOfURL(u), u, e, gc))
	}
	for _, c := range cmds {
		cc := call
		cc.Command = c
		r.add(checkBash(cc, gc))
	}
	for _, m := range models {
		cc := call
		cc.Model = m
		r.add(checkModel(cc, gc))
	}
	if write && len(paths)+len(urls)+len(cmds) == 0 {
		r.add(core.Verdict{Decision: askOrDeny(gc), Reason: "write-like tool " + call.Tool + " with no checkable target", Rule: "guard.unknown_tool"})
	}
	return r.done()
}

const maxWalk = 20000

// checkSearch judges Grep/Glob: reading the search root as a whole must not
// expose secret_reads / sandbox.no_read files, unless a single positive glob
// provably excludes every matching file.
func checkSearch(call core.ToolCall, gc core.GuardContext) core.Verdict {
	var r result
	roots := call.Paths
	if len(roots) == 0 {
		roots = []string{cwdBase(call.Cwd, gc)}
	}
	vals := scanRaw(call.Raw)
	filters := rawByKey(vals, "glob")
	if !strings.EqualFold(call.Tool, "grep") { // Glob: `pattern` is the file filter
		filters = append(filters, rawByKey(vals, "pattern")...)
	}
	for _, p := range roots {
		r.add(checkPath(p, false, call, gc, false))
		r.add(searchSecrets(resolve(p, call.Cwd, gc), secretList(gc), filters, gc))
	}
	return r.done()
}

// searchSecrets walks t and denies when a secret file lies below it. Directory
// entries never decide when a glob is given: their files do.
func searchSecrets(t target, list, globPats []string, gc core.GuardContext) core.Verdict {
	root := evalPrefix(filepath.Clean(gc.Root))
	var hit core.Verdict
	count := 0
	_ = filepath.WalkDir(t.abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped; the walk itself is best effort
		}
		if d.IsDir() && p != t.abs && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
			return fs.SkipDir
		}
		if count++; count > maxWalk {
			hit = core.Verdict{Decision: askOrDeny(gc), Reason: "search root too large to verify that it holds no secrets", Rule: "enforcement.secret_reads"}
			return fs.SkipAll
		}
		tg := target{abs: p}
		if rel, err := filepath.Rel(root, p); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			tg.rel, tg.inside = filepath.ToSlash(rel), true
		}
		pat, ok := matchesRule(list, tg, gc)
		if !ok || (d.IsDir() && len(globPats) > 0) {
			return nil
		}
		if !d.IsDir() {
			sub, _ := filepath.Rel(t.abs, p)
			if excludedByGlob(globPats, filepath.ToSlash(sub), filepath.Base(p)) {
				return nil
			}
		}
		hit = core.Verdict{Decision: core.Deny, Reason: "search would expose secret path " + p, Rule: "enforcement.secret_reads: " + pat}
		return fs.SkipAll
	})
	return hit
}

// excludedByGlob is true only for ONE plain positive glob that does not match
// the file (relative to the search root, or by base name). Negations, lists,
// braces and several filters never exclude.
func excludedByGlob(globPats []string, rel, base string) bool {
	if len(globPats) != 1 {
		return false
	}
	g := globPats[0]
	if g == "" || strings.ContainsAny(g, "!, \t\n{") {
		return false
	}
	return !matchPath(g, rel) && !matchPath(g, base)
}
