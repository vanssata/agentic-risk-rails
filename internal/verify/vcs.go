package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

var fullSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// HeadSHA is the full commit id of HEAD; the flow records it as base_sha.
func HeadSHA(ctx context.Context, root string) (string, error) {
	out, err := vcs(ctx, root, "rev-parse", "--verify", "--end-of-options", "HEAD")
	return strings.TrimSpace(out), err
}

// diffNames lists files differing from rev (a full hex SHA, or the literal HEAD),
// without rename detection (a rename is a delete plus an add).
func diffNames(ctx context.Context, root, rev string) ([]string, error) {
	if rev != "HEAD" && !fullSHA.MatchString(rev) {
		return nil, fmt.Errorf("verify: %q is not a full commit id", rev)
	}
	out, err := vcs(ctx, root, "diff", "--no-renames", "--name-only", "-z", "--end-of-options", rev, "--")
	return nul(out), err
}

func visible(paths []string) []string {
	var kept []string
	for _, p := range paths {
		if notRR(p) {
			kept = append(kept, p)
		}
	}
	return uniq(kept)
}

// GitChanged lists files changed against HEAD plus untracked (not ignored) ones.
// It is a preview for `rr affected`; task scope checks use TaskChanged.
func GitChanged(ctx context.Context, root string) ([]string, error) {
	diff, err := diffNames(ctx, root, "HEAD")
	if err != nil {
		return nil, err
	}
	untracked, err := vcs(ctx, root, "ls-files", "-o", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	return visible(append(diff, nul(untracked)...)), nil
}

// Manifest maps every file of the tree (tracked, untracked and, if asked,
// ignored; nested repositories and submodule worktrees included; only the root
// `.git` and `.rr` are skipped) to its mode and content hash.
type Manifest map[string]string

func buildManifest(ctx context.Context, root string, includeIgnored bool) (Manifest, error) {
	skip := map[string]bool{}
	if !includeIgnored {
		out, err := vcs(ctx, root, "ls-files", "-o", "-i", "--exclude-standard", "-z")
		if err != nil {
			return nil, err
		}
		for _, p := range nul(out) {
			skip[p] = true
		}
	}
	m := Manifest{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if rel == ".git" || rel == ".rr" {
				return filepath.SkipDir
			}
			return nil
		}
		if skip[rel] {
			return nil
		}
		h, err := hashPath(p)
		if err != nil {
			return fmt.Errorf("verify: manifest %s: %w", rel, err)
		}
		m[rel] = h
		return nil
	})
	return m, err
}

func hashPath(p string) (string, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if fi.Mode()&os.ModeSymlink != 0 {
		t, err := os.Readlink(p)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(h, t)
	} else {
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%o:%s", fi.Mode(), hex.EncodeToString(h.Sum(nil))), nil
}

// Baseline is what the flow calls at task start: the full manifest (JSON, to be
// written to .rr/run/<task>.baseline.json) and its sha256 (task_started.baseline).
func Baseline(ctx context.Context, root string) (manifest []byte, sha string, err error) {
	m, err := buildManifest(ctx, root, true)
	if err != nil {
		return nil, "", err
	}
	manifest, err = json.Marshal(m) // map keys are sorted: deterministic
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(manifest)
	return manifest, hex.EncodeToString(sum[:]), nil
}

// TaskChanged lists every path whose state differs from the task baseline:
// the diff against base_sha, plus every added, changed or deleted path of the
// manifest. With includeIgnored=false, ignored paths are left out (they are not
// test inputs, e.g. caches); scope checks use true.
func TaskChanged(ctx context.Context, root string, t Trust, includeIgnored bool) ([]string, error) {
	out, err := diffNames(ctx, root, t.BaseSHA)
	if err != nil {
		return nil, err
	}
	cur, err := buildManifest(ctx, root, true)
	if err != nil {
		return nil, err
	}
	var ignored map[string]bool
	if !includeIgnored {
		list, err := vcs(ctx, root, "ls-files", "-o", "-i", "--exclude-standard", "-z")
		if err != nil {
			return nil, err
		}
		ignored = map[string]bool{}
		for _, p := range nul(list) {
			ignored[p] = true
		}
	}
	for p, h := range cur {
		if t.Manifest[p] != h && !ignored[p] {
			out = append(out, p)
		}
	}
	for p := range t.Manifest {
		if _, ok := cur[p]; !ok && !ignored[p] {
			out = append(out, p)
		}
	}
	return visible(out), nil
}

// TreeFingerprint hashes HEAD, the index and the manifest of the tree. Without
// includeIgnored, ignored files (caches) are not part of it.
func TreeFingerprint(ctx context.Context, root string, includeIgnored bool) (string, error) {
	head, err := vcs(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	index, err := vcs(ctx, root, "ls-files", "-s", "-z")
	if err != nil {
		return "", err
	}
	m, err := buildManifest(ctx, root, includeIgnored)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintln(h, strings.TrimSpace(head))
	h.Write([]byte(index))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}
