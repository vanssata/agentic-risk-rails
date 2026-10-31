package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
		"-c", "core.untrackedCache=false", "-c", "diff.external=", "--no-pager",
	}
	c := exec.CommandContext(ctx, "git", append(hard, args...)...)
	c.Dir = root
	c.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	var out, stderr bytes.Buffer
	c.Stdout, c.Stderr = &out, &stderr
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("verify: vcs %s: %w: %s", args[0], err, stderr.String())
	}
	return out.String(), nil
}

// ChangedFiles lists files changed against base (default HEAD) plus untracked ones.
func ChangedFiles(ctx context.Context, root, base string) ([]string, error) {
	if base == "" {
		base = "HEAD"
	}
	diff, err := vcs(ctx, root, "diff", "--name-only", "-z", base, "--")
	if err != nil {
		return nil, err
	}
	untracked, err := vcs(ctx, root, "ls-files", "-o", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range strings.Split(diff+untracked, "\x00") {
		if s != "" {
			out = append(out, s)
		}
	}
	return uniq(out), nil
}

// TreeFingerprint hashes HEAD and the content of every changed file, so any edit
// after a verify run changes it.
func TreeFingerprint(ctx context.Context, root string) (string, error) {
	head, err := vcs(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	files, err := ChangedFiles(ctx, root, "")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintln(h, strings.TrimSpace(head))
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(root, f)) // deleted file: empty content, name still hashed
		fmt.Fprintf(h, "%s\x00%d\x00", f, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
