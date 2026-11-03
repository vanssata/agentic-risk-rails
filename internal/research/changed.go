package research

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ChangedSince lists every path whose working-tree state differs from commit
// sha: tracked changes (old path of a rename or deletion included) and
// untracked files that are not ignored. Callers put it in Inv.Changed, so an
// entry is reused only for a tree equal to its sha in everything it READ, and
// nothing is cached while the list is non-empty. It is not the task baseline.
func ChangedSince(ctx context.Context, root, sha string) ([]string, error) {
	if !shaRe.MatchString(sha) {
		return nil, fmt.Errorf("research: bad sha %q", sha)
	}
	var out []string
	for _, args := range [][]string{
		{"diff", "--name-only", "-z", "--no-renames", sha, "--"},
		{"ls-files", "-z", "--others", "--exclude-standard"},
	} {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("research: git %s: %w", args[0], err)
		}
		for _, p := range strings.Split(string(b), "\x00") {
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
