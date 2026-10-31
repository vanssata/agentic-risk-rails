package triage

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const readLimit = 1 << 20

// pathSuffixes: such files are loaded by path, not by name, so the path is the needle.
var pathSuffixes = []string{".twig", ".html", ".htm", ".yaml", ".yml", ".json", ".toml", ".ini", ".xml", ".conf", ".cfg", ".env", ".j2", ".tpl", ".neon"}

// Load reads the existing files among files (at most 1 MB each, text only)
// and counts, for each, how many other non-test tree files mention it: its
// identifier as a whole word, or its path for config/template files.
// Files that do not exist on disk are new and get no entry in refs.
func Load(root string, files, tree, testGlobs []string) (refs map[string]int, content map[string]string) {
	refs, content = map[string]int{}, map[string]string{}
	words := map[string]*regexp.Regexp{}
	for _, f := range files {
		text, ok := readText(root, f)
		if !ok {
			if _, err := os.Stat(filepath.Join(root, f)); err != nil {
				continue
			}
		}
		refs[f], content[f] = 0, text
		if !hasSuffix(f) {
			words[f] = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])` + regexp.QuoteMeta(ident(f)) + `(?:$|[^A-Za-z0-9_])`)
		}
	}
	for _, t := range tree {
		if anyMatch(testGlobs, t) != "" {
			continue
		}
		text, ok := readText(root, t)
		if !ok {
			continue
		}
		for f := range refs {
			if f == t {
				continue
			}
			if rx := words[f]; (rx != nil && rx.MatchString(text)) || (rx == nil && strings.Contains(text, f)) {
				refs[f]++
			}
		}
	}
	return refs, content
}

func hasSuffix(f string) bool {
	e := path.Ext(f)
	for _, s := range pathSuffixes {
		if e == s {
			return true
		}
	}
	return false
}

func readText(root, rel string) (string, bool) {
	fh, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		return "", false
	}
	defer fh.Close()
	buf := make([]byte, readLimit)
	n, _ := fh.Read(buf)
	buf = buf[:n]
	if bytes.IndexByte(buf[:min(n, 8192)], 0) >= 0 {
		return "", false
	}
	return string(buf), true
}
