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
// tools it knows.

var (
	rawPathKeys  = opts("path", "filepath", "paths", "file", "files", "filename", "target", "destination", "dest")
	rawURLKeys   = opts("url", "uri", "href")
	rawCmdKeys   = opts("command", "cmd")
	rawModelKeys = opts("model")
	camelRe      = regexp.MustCompile(`[A-Z]?[a-z0-9]+|[A-Z]+`)
	writeVerbs   = opts("write", "create", "edit", "delete", "remove", "move", "rename", "put", "upload", "patch", "append", "save", "update", "mkdir", "touch", "copy", "replace", "insert", "apply", "push", "publish", "send", "set")
)

// scanRaw collects string values by normalised key (lower case, no _ or -).
func scanRaw(raw json.RawMessage) map[string][]string {
	out := map[string][]string{}
	if len(raw) == 0 {
		return out
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return out
	}
	n := 0
	var walk func(v any, key string, depth int)
	walk = func(v any, key string, depth int) {
		if depth > 8 || n > 500 {
			return
		}
		n++
		switch x := v.(type) {
		case string:
			if key != "" {
				out[key] = append(out[key], x)
			}
		case []any:
			for _, e := range x {
				walk(e, key, depth+1)
			}
		case map[string]any:
			for k, e := range x {
				walk(e, strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k)), depth+1)
			}
		}
	}
	walk(v, "", 0)
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

// checkUnknownTool applies the path, egress, shell and model rules to whatever
// a tool carries in its raw input.
func checkUnknownTool(call core.ToolCall, gc core.GuardContext) core.Verdict {
	var r result
	e := gc.Policy.Policy.Enforcement
	fields := map[string][]string{}
	if call.Command == "" && !strings.EqualFold(call.Tool, "bash") {
		fields = scanRaw(call.Raw)
	}
	var paths, urls, cmds, models []string
	paths = append(paths, call.Paths...)
	for k, vs := range fields {
		switch {
		case rawPathKeys[k]:
			paths = append(paths, vs...)
		case rawURLKeys[k]:
			urls = append(urls, vs...)
		case rawCmdKeys[k]:
			cmds = append(cmds, vs...)
		case rawModelKeys[k]:
			models = append(models, vs...)
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
		r.add(checkPath(p, true, call, gc, false))
		if !write {
			r.add(checkPath(p, false, call, gc, false))
		}
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

const maxWalk = 30000

// checkSearch judges Grep/Glob: reading the search root as a whole must not
// expose secret_reads / sandbox.no_read files, unless the glob provably
// excludes every matching file.
func checkSearch(call core.ToolCall, gc core.GuardContext) core.Verdict {
	var r result
	roots := call.Paths
	if len(roots) == 0 {
		roots = []string{cwdBase(call.Cwd, gc)}
	}
	e := gc.Policy.Policy.Enforcement
	list := append(append([]string{}, e.SecretReads...), expandRefs(e.Sandbox.NoRead, e)...)
	f := scanRaw(call.Raw)
	filters := append(append([]string{}, f["glob"]...), f["pattern"]...)
	if call.Tool == "Grep" || strings.EqualFold(call.Tool, "grep") {
		filters = f["glob"] // a Grep pattern is a regex, not a file filter
	}
	for _, p := range roots {
		r.add(checkPath(p, false, call, gc, false))
		r.add(searchSecrets(resolve(p, call.Cwd, gc), list, filters, gc))
	}
	return r.done()
}

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
		if !ok {
			return nil
		}
		if !d.IsDir() && excludedByGlob(globPats, tg.rel, p) {
			return nil
		}
		hit = core.Verdict{Decision: core.Deny, Reason: "search would expose secret path " + p, Rule: "enforcement.secret_reads: " + pat}
		return fs.SkipAll
	})
	return hit
}

// excludedByGlob is true when a glob filter is given and does not match the file.
func excludedByGlob(globPats []string, rel, abs string) bool {
	if len(globPats) == 0 {
		return false
	}
	for _, g := range globPats {
		if matchPath(g, rel) || matchPath(g, filepath.Base(abs)) {
			return false
		}
	}
	return true
}
