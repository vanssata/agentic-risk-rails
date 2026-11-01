package verify

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

var skipDirs = map[string]bool{".git": true, "vendor": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, ".rr": true}

// walkFiles returns repo-relative, slash-separated paths of files accepted by keep.
func walkFiles(root string, keep func(rel string) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel = filepath.ToSlash(rel); keep(rel) {
			out = append(out, rel)
		}
		return nil
	})
	return out, err
}

const maxReadSize = 4 << 20

// readFile reads a regular file of the repository. A symlink, FIFO, device,
// socket or oversized file is an error (fail-closed): content that decides test
// selection must not come from outside the tree or block the reader.
func readFile(root, rel string) (string, error) {
	p := filepath.Join(root, rel)
	fi, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("verify: refusing to read %s: not a regular file", rel)
	}
	if fi.Size() > maxReadSize {
		return "", fmt.Errorf("verify: refusing to read %s: larger than %d bytes", rel, maxReadSize)
	}
	b, err := os.ReadFile(p)
	return string(b), err
}

func exists(root, rel string) bool {
	_, err := os.Stat(filepath.Join(root, rel))
	return err == nil
}

// uniq returns the sorted distinct elements of s.
func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
