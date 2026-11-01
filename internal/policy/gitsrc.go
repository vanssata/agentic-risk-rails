package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/gitx"
)

const policyFile = "riskrails.yaml"

func gitOut(ctx context.Context, root string, args ...string) ([]byte, error) {
	return gitx.Run(ctx, "", append([]string{"-C", root}, args...)...)
}

func splitNUL(out []byte) []string {
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files
}

// ListFiles returns the tracked and untracked (not ignored) files of the
// checkout, for glob-set comparison.
func ListFiles(ctx context.Context, root string) ([]string, error) {
	out, err := gitOut(ctx, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	return splitNUL(out), nil
}

// ListFilesAt returns the files of the tree at ref. The index is under the
// agent's control (`git rm --cached`); a committed tree is not.
func ListFilesAt(ctx context.Context, root, ref string) ([]string, error) {
	sha, err := ResolveRef(ctx, root, ref)
	if err != nil {
		return nil, err
	}
	out, err := gitOut(ctx, root, "ls-tree", "-r", "-z", "--name-only", sha)
	if err != nil {
		return nil, err
	}
	return splitNUL(out), nil
}

// ResolveRef turns a user-supplied ref into a commit SHA. Accepted forms only:
// HEAD; a fully qualified refs/... name; a bare short name that exists in
// exactly one of refs/heads, refs/tags, refs/remotes (a forged tag `origin/main`
// next to the remote branch is ambiguous and rejected); a full 40/64-hex SHA
// that is a commit and is not also the name of a ref. Revision syntax
// (~ ^ @ : { ..) and leading "-" are rejected, so no suffix can steer git to a
// different object than the one named.
func ResolveRef(ctx context.Context, root, name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "~^@:{ \t\n\\") || strings.Contains(name, "..") {
		return "", fmt.Errorf("policy: invalid ref %q", name)
	}
	target := name
	switch {
	case name == "HEAD":
	case strings.HasPrefix(name, "refs/"):
		if !refExists(ctx, root, name) {
			return "", fmt.Errorf("policy: unknown ref %q", name)
		}
	case hexSHA.MatchString(name):
		for _, ns := range []string{"refs/heads/", "refs/tags/", "refs/remotes/"} {
			if refExists(ctx, root, ns+name) {
				return "", fmt.Errorf("policy: %q is both a SHA and a ref name; use the fully qualified ref", name)
			}
		}
		if _, err := gitOut(ctx, root, "cat-file", "-e", name+"^{commit}"); err != nil {
			return "", fmt.Errorf("policy: unknown commit %q", name)
		}
	default:
		var found []string
		for _, ns := range []string{"refs/heads/", "refs/tags/", "refs/remotes/"} {
			if refExists(ctx, root, ns+name) {
				found = append(found, ns+name)
			}
		}
		switch len(found) {
		case 0:
			return "", fmt.Errorf("policy: unknown ref %q", name)
		case 1:
			target = found[0]
		default:
			return "", fmt.Errorf("policy: ref %q is ambiguous (%s); use a fully qualified ref", name, strings.Join(found, ", "))
		}
	}
	out, err := gitOut(ctx, root, "rev-parse", "--verify", "--quiet", "--end-of-options", target+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("policy: unknown ref %q", name)
	}
	return strings.TrimSpace(string(out)), nil
}

var hexSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

func refExists(ctx context.Context, root, ref string) bool {
	_, err := gitOut(ctx, root, "show-ref", "--verify", "--quiet", ref)
	return err == nil
}

func displayRef(ref string) string {
	return strings.TrimPrefix(strings.TrimPrefix(ref, "refs/remotes/"), "refs/heads/")
}

// ReadAtRef loads riskrails.yaml as committed at ref (see ResolveRef). A ref
// without the file yields StrictDefaults (DES §3.1); an unknown or ambiguous
// ref is an error.
func ReadAtRef(ctx context.Context, root, ref string) (core.Layer, error) {
	sha, err := ResolveRef(ctx, root, ref)
	if err != nil {
		return core.Layer{}, err
	}
	source := "git:" + displayRef(ref) + ":" + policyFile
	// `git show` exits 128 both for a bad ref and for an absent file; ls-tree tells them apart.
	listed, err := gitOut(ctx, root, "ls-tree", "--name-only", sha, "--", policyFile)
	if err != nil {
		return core.Layer{}, fmt.Errorf("policy: %w", err)
	}
	if len(bytes.TrimSpace(listed)) == 0 {
		return core.Layer{Policy: core.StrictDefaults(), Source: source + " (absent: strict defaults)"}, nil
	}
	raw, err := gitOut(ctx, root, "show", sha+":"+policyFile)
	if err != nil {
		return core.Layer{}, fmt.Errorf("policy: %w", err)
	}
	p, err := Load(raw)
	if err != nil {
		return core.Layer{}, fmt.Errorf("%s: %w", source, err)
	}
	return core.Layer{Policy: p, Raw: raw, Source: source}, nil
}

// InForce reads the policy in force: riskrails.yaml of the default branch.
// The branch is origin/HEAD, else main, else master; refs/remotes/origin/<b>
// is preferred and refs/heads/<b> is the fallback when there is no remote
// (DES §3.4 step 3). Only fully qualified refs are used, so tags cannot shadow
// them. No such branch => StrictDefaults.
//
// TRUST: refs/remotes/origin/* and origin/HEAD are writable by the agent
// locally (`git update-ref`), so this read is a tripwire, not a boundary. Until
// the wave-3 runner pins a trusted SHA (or fetches), CI must pass `--base` as a
// SHA obtained from the hosting API.
func InForce(ctx context.Context, root string) (core.Layer, error) {
	ref, ok := DefaultRef(ctx, root)
	if !ok {
		return core.Layer{Policy: core.StrictDefaults(), Source: "default branch not found (strict defaults)"}, nil
	}
	l, err := ReadAtRef(ctx, root, ref)
	if err != nil {
		return l, err
	}
	// An explicit project.default_branch (not the defaulted "main") wins over the guessed branch.
	if raw, derr := decode(l.Raw); derr == nil && raw.Project.DefaultBranch != "" {
		b := raw.Project.DefaultBranch
		if r, ok := DefaultRefFor(ctx, root, b); ok && r != ref {
			return ReadAtRef(ctx, root, r)
		}
	}
	return l, nil
}

// DefaultRef returns the fully-qualified ref of the default branch that
// InForce reads (same selection and trust caveats); ok=false if none exists.
func DefaultRef(ctx context.Context, root string) (ref string, ok bool) {
	return DefaultRefFor(ctx, root, "")
}

// DefaultRefFor is DefaultRef preferring origin/<branch> (project.default_branch)
// when branch is set and exists, then refs/heads/<branch>; else DefaultRef's choice.
func DefaultRefFor(ctx context.Context, root, branch string) (ref string, ok bool) {
	const remote = "refs/remotes/origin/"
	var refs []string
	if branch != "" && !strings.HasPrefix(branch, "-") && !strings.Contains(branch, "..") {
		for _, r := range []string{remote + branch, "refs/heads/" + branch} {
			if _, err := gitOut(ctx, root, "show-ref", "--verify", "--quiet", r); err == nil {
				return r, true
			}
		}
	}
	if out, err := gitOut(ctx, root, "symbolic-ref", "refs/remotes/origin/HEAD"); err == nil {
		r := strings.TrimSpace(string(out))
		refs = []string{r, "refs/heads/" + strings.TrimPrefix(r, remote)}
	} else {
		refs = []string{remote + "main", "refs/heads/main", remote + "master", "refs/heads/master"}
	}
	for _, r := range refs {
		if _, err := gitOut(ctx, root, "show-ref", "--verify", "--quiet", r); err == nil {
			return r, true
		}
	}
	return "", false
}

var ceilingOverride *[2]string

// CeilingPaths returns the enterprise and user ceiling files.
func CeilingPaths() (enterprise, user string) {
	if ceilingOverride != nil {
		return ceilingOverride[0], ceilingOverride[1]
	}
	home, _ := os.UserHomeDir()
	return "/etc/riskrails/ceiling.yaml", filepath.Join(home, ".config", "riskrails", "ceiling.yaml")
}

// SetCeilingPaths overrides CeilingPaths (tests); call the result to restore.
func SetCeilingPaths(enterprise, user string) (restore func()) {
	prev := ceilingOverride
	ceilingOverride = &[2]string{enterprise, user}
	return func() { ceilingOverride = prev }
}

// LoadCeilings reads both ceiling files; an absent file is a nil layer, an
// unreadable or invalid one is an error (the caller halts).
func LoadCeilings() (enterprise, user *core.Layer, err error) {
	ep, up := CeilingPaths()
	if enterprise, err = readCeiling(ep); err != nil {
		return nil, nil, err
	}
	if user, err = readCeiling(up); err != nil {
		return nil, nil, err
	}
	return enterprise, user, nil
}

func readCeiling(path string) (*core.Layer, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy: ceiling %s: %w", path, err)
	}
	p, err := LoadCeiling(raw)
	if err != nil {
		return nil, fmt.Errorf("ceiling %s: %w", path, err)
	}
	return &core.Layer{Policy: p, Raw: raw, Source: path}, nil
}
