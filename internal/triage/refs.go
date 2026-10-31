package triage

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const readLimit = 1 << 20

// pathSuffixes: such files are loaded by path, not by name, so the path is the needle.
var pathSuffixes = []string{".twig", ".html", ".htm", ".yaml", ".yml", ".json", ".toml", ".ini", ".xml", ".conf", ".cfg", ".env", ".j2", ".tpl", ".neon"}

type readState int

const (
	readOK      readState = iota
	readMissing           // does not exist
	readOpaque            // exists but cannot be trusted to be read in full: binary, over the cap, symlink, unreadable, outside root
)

// Load reads the existing files among files (text only) and counts, for each,
// how many other non-test tree files mention it: its identifier as a whole
// word, or its path for config/template files. A file that is missing gets no
// entry in refs (new, unless the caller lists it as deleted). A file that is
// binary, over 1 MB, a symlink, unreadable, absolute or contains ".." is
// reported in unreadable (and never followed): triage scores it upward.
func Load(root string, files, tree, testGlobs []string) (refs map[string]int, content map[string]string, unreadable map[string]bool) {
	refs, content, unreadable = map[string]int{}, map[string]string{}, map[string]bool{}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		rootReal = root
	}
	words := map[string]*regexp.Regexp{}
	for _, f := range files {
		text, st := readText(root, rootReal, f)
		if st == readMissing {
			continue
		}
		refs[f], content[f] = 0, text
		if st == readOpaque {
			unreadable[f] = true
		}
		if !hasSuffix(f) {
			words[f] = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])` + regexp.QuoteMeta(ident(f)) + `(?:$|[^A-Za-z0-9_])`)
		}
	}
	for _, t := range tree {
		if anyMatch(testGlobs, t) != "" {
			continue
		}
		text, st := readText(root, rootReal, t)
		if st != readOK {
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
	return refs, content, unreadable
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

func readText(root, rootReal, rel string) (string, readState) {
	clean := filepath.ToSlash(rel)
	if filepath.IsAbs(rel) || strings.HasPrefix(clean, "/") {
		return "", readOpaque
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", readOpaque
		}
	}
	p := filepath.Join(root, rel)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", readMissing
	}
	if err != nil || !fi.Mode().IsRegular() { // a symlink is never followed
		return "", readOpaque
	}
	if real, err := filepath.EvalSymlinks(p); err != nil || !strings.HasPrefix(real, rootReal+string(filepath.Separator)) {
		return "", readOpaque
	}
	fh, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", readOpaque
	}
	defer fh.Close()
	buf, err := io.ReadAll(io.LimitReader(fh, readLimit+1))
	if err != nil || len(buf) > readLimit || bytes.IndexByte(buf[:min(len(buf), 8192)], 0) >= 0 {
		return "", readOpaque
	}
	return string(buf), readOK
}
