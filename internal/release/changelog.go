package release

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var linkRefRe = regexp.MustCompile(`^\[[^\]]+\]:\s`)

// CheckChangelog requires a non-empty section in root/CHANGELOG.md (Keep a Changelog):
// "## [version]" when version != "", else "## [Unreleased]".
func CheckChangelog(root, version string) error {
	b, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		return fmt.Errorf("changelog: %w", err)
	}
	want := "Unreleased"
	if version != "" {
		want = version
	}
	in, found, body := false, false, false
	for _, l := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "## ") {
			if in {
				break
			}
			h := strings.TrimLeft(strings.TrimSpace(t[3:]), "[")
			if i := strings.IndexAny(h, " ]"); i >= 0 {
				h = h[:i]
			}
			in = strings.EqualFold(h, want)
			found = found || in
			continue
		}
		if in && t != "" && !strings.HasPrefix(t, "#") && !linkRefRe.MatchString(t) {
			body = true
		}
	}
	if !found {
		return fmt.Errorf("changelog: no section for %q", want)
	}
	if !body {
		return fmt.Errorf("changelog: section %q is empty", want)
	}
	return nil
}
