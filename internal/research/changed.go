package research

import (
	"context"
	"fmt"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/gitx"
)

// ChangedSince lists every path whose working-tree state differs from commit
// sha: tracked changes (old path of a rename or deletion included) and
// untracked files that are not ignored. Callers put it in Inv.Changed, so an
// entry is reused only for a tree equal to its sha in everything it READ, and
// nothing is cached while the list is non-empty. It is not the task baseline.
// rr's own state (.rr/) is not part of the scouted tree. git is hardened (gitx):
// the repo's config must not run anything.
func ChangedSince(ctx context.Context, root, sha string) ([]string, error) {
	if !shaRe.MatchString(sha) {
		return nil, fmt.Errorf("research: bad sha %q", sha)
	}
	var out []string
	for _, args := range [][]string{
		{"diff", "--name-only", "-z", "--no-renames", sha, "--"},
		{"ls-files", "-z", "--others", "--exclude-standard"},
	} {
		b, err := gitx.Run(ctx, "", append([]string{"-C", root}, args...)...)
		if err != nil {
			return nil, fmt.Errorf("research: git %s: %w", args[0], err)
		}
		for _, p := range strings.Split(string(b), "\x00") {
			if p != "" && p != ".rr" && !strings.HasPrefix(p, ".rr/") {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
