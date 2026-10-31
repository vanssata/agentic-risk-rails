package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

const policyFile = "riskrails.yaml"

func gitOut(ctx context.Context, root string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// ListFiles returns `git ls-files` of the checkout, for glob-set comparison.
func ListFiles(ctx context.Context, root string) ([]string, error) {
	out, err := gitOut(ctx, root, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// ReadAtRef loads riskrails.yaml as committed at ref. A ref without the file
// yields StrictDefaults (DES §3.1); an unknown ref is an error.
func ReadAtRef(ctx context.Context, root, ref string) (core.Layer, error) {
	if ref == "" || strings.HasPrefix(ref, "-") {
		return core.Layer{}, fmt.Errorf("policy: invalid ref %q", ref)
	}
	source := "git:" + ref + ":" + policyFile
	// `git show` exits 128 both for a bad ref and for an absent file; ls-tree tells them apart.
	listed, err := gitOut(ctx, root, "ls-tree", "--name-only", ref, "--", policyFile)
	if err != nil {
		return core.Layer{}, fmt.Errorf("policy: %w", err)
	}
	if len(bytes.TrimSpace(listed)) == 0 {
		return core.Layer{Policy: core.StrictDefaults(), Source: source + " (absent: strict defaults)"}, nil
	}
	raw, err := gitOut(ctx, root, "show", ref+":"+policyFile)
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
// The branch is origin/HEAD, else main, else master; origin/<branch> is
// preferred and the local branch is the fallback when there is no remote
// (DES §3.4 step 3). No such branch or no file there ⇒ StrictDefaults.
func InForce(ctx context.Context, root string) (core.Layer, error) {
	var refs []string
	if out, err := gitOut(ctx, root, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"); err == nil {
		remote := strings.TrimSpace(string(out))
		refs = []string{remote, strings.TrimPrefix(remote, "origin/")}
	} else {
		refs = []string{"origin/main", "main", "origin/master", "master"}
	}
	for _, ref := range refs {
		if _, err := gitOut(ctx, root, "rev-parse", "--verify", "--quiet", ref+"^{commit}"); err == nil {
			return ReadAtRef(ctx, root, ref)
		}
	}
	return core.Layer{Policy: core.StrictDefaults(), Source: "default branch not found (strict defaults)"}, nil
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
