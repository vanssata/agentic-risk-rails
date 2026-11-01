package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Golang selects packages whose test binary depends on a changed package:
// `go list -test -json` gives every test binary its recursive Deps, which is the
// reverse dependency graph.
type Golang struct{}

func (Golang) Name() string { return "go" }

func (Golang) Detect(root string) bool { return exists(root, "go.mod") }

type goPkg struct {
	ImportPath string
	Dir        string
	Deps       []string
}

func stripVariant(p string) string {
	if i := strings.Index(p, " ["); i >= 0 {
		return p[:i]
	}
	return p
}

func (Golang) Map(ctx context.Context, root string, changed []string) (tests, uncovered []string, err error) {
	var out, stderr bytes.Buffer
	c, err := hostCmd(ctx, root, "go", "list", "-test", "-json=ImportPath,Dir,Deps", "./...")
	if err != nil {
		return nil, nil, err
	}
	c.Stdout, c.Stderr = &out, &stderr
	if err := c.Run(); err != nil {
		return nil, nil, fmt.Errorf("verify: go list: %w: %s", err, stderr.String())
	}
	dirToPkg := map[string]string{} // rel dir -> import path
	var bins []goPkg                // test binaries
	dec := json.NewDecoder(&out)
	for dec.More() {
		var p goPkg
		if err := dec.Decode(&p); err != nil {
			return nil, nil, fmt.Errorf("verify: go list output: %w", err)
		}
		switch {
		case strings.HasSuffix(p.ImportPath, ".test"):
			bins = append(bins, p)
		case !strings.Contains(p.ImportPath, " ["):
			rel, err := filepath.Rel(root, p.Dir)
			if err != nil {
				return nil, nil, err
			}
			dirToPkg[filepath.ToSlash(rel)] = p.ImportPath
		}
	}
	pkgToDir := map[string]string{}
	for d, ip := range dirToPkg {
		pkgToDir[ip] = d
	}
	for _, f := range changed {
		var ip string
		for d := path.Dir(f); ; d = path.Dir(d) {
			if p, ok := dirToPkg[d]; ok {
				ip = p
				break
			}
			if d == "." {
				break
			}
		}
		if ip == "" {
			uncovered = append(uncovered, f)
			continue
		}
		found := false
		for _, b := range bins {
			hit := strings.TrimSuffix(b.ImportPath, ".test") == ip
			for _, d := range b.Deps {
				hit = hit || stripVariant(d) == ip
			}
			if hit {
				tests, found = append(tests, "./"+strings.TrimPrefix(pkgToDir[strings.TrimSuffix(b.ImportPath, ".test")], "./")), true
			}
		}
		if !found {
			uncovered = append(uncovered, f)
		}
	}
	return uniq(tests), uniq(uncovered), nil
}

func (Golang) Run(ctx context.Context, root string, spec core.VerifyAdapterSpec, tests []string, full bool) (core.TestResult, error) {
	return runCmd(ctx, root, spec, tests, full)
}
