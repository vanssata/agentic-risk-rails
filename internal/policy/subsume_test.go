package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/globs"
)

func TestSubsumes(t *testing.T) {
	for _, c := range []struct {
		q, p string
		want bool
	}{
		{"src/Payment/**", "src/Payment/**", true},
		{"src/Payment/**", "src/Payment/*.php", true},
		{"src/Payment/**", "src/Payment/**/x", true},
		{"src/Payment/**", "src/Payment/x/**", true},
		{"src/Payment/**", "src/Payment/", false},
		{"**", "anything/at/all", true},
		{".env*", ".env.local", true},
		{"git diff*", "git diff --stat", true},
		{"dir/*", "dir/**", false}, // weakening dir/** to dir/* must not read as covered
		{"dir/*", "dir/a", true},
		{"dir/*", "dir/a/b", false},
		{"a*", "a[!a]*", false}, // a negated class matches "/"
		{"a*", "a?", false},
		{"a*", "a*b", false},
		{"**/**", "**/", false},
		{"a**", "ab", false},
	} {
		assert.Equal(t, c.want, subsumes(c.q, c.p), "%q covers %q", c.q, c.p)
	}
}

var probePaths = []string{
	"a", "ab", "a/b", "a/b/c", "dir", "dir/a", "dir/a/b", "dir/x/y/z", "dir/", ".env", ".env.local", "config/.env",
	"src/Payment/A.php", "src/Payment/Sub/B.php", "src/Util/c", "x", "x/y", "git diff", "git diff --stat", "aa", "a1", "a-", "b/a",
}

// pathsFor derives probe paths from a pattern by substituting its wildcards.
func pathsFor(pat string) []string {
	return []string{
		strings.NewReplacer("**", "x/y", "*", "a", "?", "b", "[!a]", "/", "[", "", "]", "", "{", "", "}", "", ",", "").Replace(pat),
		strings.NewReplacer("**", "", "*", "", "?", "q", "[!a]", "b").Replace(pat),
		strings.NewReplacer("**", "x/y/z", "*", "a/b", "?", "/").Replace(pat),
		strings.NewReplacer("**", "x", "*", "", "[!a]", "/b").Replace(pat),
	}
}

// FuzzSubsumes: whenever subsumes(q, p) holds, nothing p matches may escape q.
// Seeds are the found counterexamples and the table above; `go test -fuzz`
// extends them.
func FuzzSubsumes(f *testing.F) {
	for _, s := range [][2]string{
		{"dir/*", "dir/**"}, {"a*", "a[!a]*"}, {"**/**", "**/"}, {"src/**", "src/a/**"}, {".env*", ".env.x"},
		{"dir/**", "dir/**/x"}, {"a*", "a/b"}, {"a/*", "a/*"}, {"*", "a"}, {"a**", "a/b"}, {"x/*", "x/[!a]"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, q, p string) {
		if !globs.Valid(q) || !globs.Valid(p) || !subsumes(q, p) {
			return
		}
		paths := append(append(append([]string{}, probePaths...), pathsFor(p)...), pathsFor(q)...)
		for _, path := range paths {
			if globs.Match(p, path) && !globs.Match(q, path) {
				t.Fatalf("subsumes(%q, %q) but %q matches only p", q, p, path)
			}
		}
	})
}
