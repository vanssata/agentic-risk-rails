package verify

import (
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

func readFile(root, rel string) string {
	b, _ := os.ReadFile(filepath.Join(root, rel))
	return string(b)
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
