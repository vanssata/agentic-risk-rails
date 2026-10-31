package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// vcs runs the version-control binary the way every rr call must (errata #16):
// hardened config, no inherited GIT_* variables, no global/system config.
func vcs(ctx context.Context, root string, args ...string) (string, error) {
	hard := []string{
		"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
		"-c", "core.sshCommand=false", "-c", "core.askPass=false", "-c", "core.alternateRefsCommand=",
		"-c", "core.untrackedCache=false", "-c", "core.attributesFile=/dev/null",
		"-c", "protocol.allow=never", "-c", "credential.helper=", "-c", "diff.external=", "--no-pager",
	}
	c := exec.CommandContext(ctx, "git", append(hard, args...)...)
	c.Dir = root
	c.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C"}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "SYSTEMROOT"} {
		if v, ok := os.LookupEnv(k); ok {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	var out, stderr bytes.Buffer
	c.Stdout, c.Stderr = &out, &stderr
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("verify: vcs %s: %w: %s", args[0], err, stderr.String())
	}
	return out.String(), nil
}

func nul(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func notRR(p string) bool { return p != ".rr" && !strings.HasPrefix(p, ".rr/") }

// ChangedFiles lists files changed against base (default HEAD): the diff
// without rename detection (a rename is a delete plus an add), untracked files,
// and files hidden from git with assume-unchanged / skip-worktree (treated as
// changed because their state cannot be trusted). `.rr/` is excluded.
func ChangedFiles(ctx context.Context, root, base string) ([]string, error) {
	if base == "" {
		base = "HEAD"
	}
	diff, err := vcs(ctx, root, "diff", "--no-renames", "--name-only", "-z", base, "--")
	if err != nil {
		return nil, err
	}
	untracked, err := vcs(ctx, root, "ls-files", "-o", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	tagged, err := vcs(ctx, root, "ls-files", "-v", "-z")
	if err != nil {
		return nil, err
	}
	out := append(nul(diff), nul(untracked)...)
	for _, e := range nul(tagged) {
		if len(e) > 2 && (e[0] >= 'a' && e[0] <= 'z' || e[0] == 'S') {
			out = append(out, e[2:])
		}
	}
	var kept []string
	for _, p := range out {
		if notRR(p) {
			kept = append(kept, p)
		}
	}
	return uniq(kept), nil
}

// TreeFingerprint hashes HEAD, the index (mode + blob of every tracked file) and
// the mode and content of every changed, untracked and ignored file (`.rr/`
// excluded). A deleted file hashes differently from an empty one; an unreadable
// file is an error.
func TreeFingerprint(ctx context.Context, root string) (string, error) {
	head, err := vcs(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	index, err := vcs(ctx, root, "ls-files", "-s", "-z")
	if err != nil {
		return "", err
	}
	changed, err := ChangedFiles(ctx, root, "")
	if err != nil {
		return "", err
	}
	all, err := vcs(ctx, root, "ls-files", "-o", "-z") // includes ignored files
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintln(h, strings.TrimSpace(head))
	h.Write([]byte(index))
	for _, f := range uniq(append(changed, nul(all)...)) {
		if !notRR(f) {
			continue
		}
		if err := hashFile(h, root, f); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(h io.Writer, root, rel string) error {
	p := filepath.Join(root, rel)
	fi, err := os.Lstat(p)
	switch {
	case os.IsNotExist(err):
		_, err = fmt.Fprintf(h, "%s\x00deleted\x00", rel)
		return err
	case err != nil:
		return fmt.Errorf("verify: fingerprint %s: %w", rel, err)
	}
	fmt.Fprintf(h, "%s\x00%o\x00", rel, fi.Mode())
	if fi.Mode()&os.ModeSymlink != 0 {
		t, err := os.Readlink(p)
		if err != nil {
			return fmt.Errorf("verify: fingerprint %s: %w", rel, err)
		}
		_, err = io.WriteString(h, t)
		return err
	}
	if fi.IsDir() {
		return nil
	}
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("verify: fingerprint %s: %w", rel, err)
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("verify: fingerprint %s: %w", rel, err)
	}
	_, err = h.Write([]byte{0})
	return err
}
