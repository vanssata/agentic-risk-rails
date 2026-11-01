package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// PHPUnit maps changed classes to tests through composer.json PSR-4 (autoload
// and autoload-dev) plus the XTest.php naming convention.
type PHPUnit struct{}

func (PHPUnit) Name() string { return "phpunit" }

func (PHPUnit) Detect(root string) bool { return exists(root, "composer.json") }

type composerFile struct {
	Autoload struct {
		PSR4 map[string]json.RawMessage `json:"psr-4"`
	} `json:"autoload"`
	AutoloadDev struct {
		PSR4 map[string]json.RawMessage `json:"psr-4"`
	} `json:"autoload-dev"`
}

type psr4Entry struct{ prefix, dir string }

// psr4 returns prefix -> dir entries, longest dir first. A value is a string or an array of strings.
func psr4(root string) ([]psr4Entry, error) {
	var c composerFile
	raw, err := readFile(root, "composer.json")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Errorf("verify: composer.json: %w", err)
	}
	var out []psr4Entry
	for _, m := range []map[string]json.RawMessage{c.Autoload.PSR4, c.AutoloadDev.PSR4} {
		for prefix, raw := range m {
			var dirs []string
			if json.Unmarshal(raw, &dirs) != nil {
				var d string
				if err := json.Unmarshal(raw, &d); err != nil {
					return nil, fmt.Errorf("verify: composer.json psr-4 %q: %w", prefix, err)
				}
				dirs = []string{d}
			}
			for _, d := range dirs {
				out = append(out, psr4Entry{prefix, strings.Trim(path.Clean(d), "/") + "/"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].dir) > len(out[j].dir) })
	return out, nil
}

func (PHPUnit) Map(_ context.Context, root string, changed []string) (tests, uncovered []string, err error) {
	entries, err := psr4(root)
	if err != nil {
		return nil, nil, err
	}
	phpTests, err := walkFiles(root, func(rel string) bool { return strings.HasSuffix(rel, "Test.php") })
	if err != nil {
		return nil, nil, err
	}
	for _, f := range changed {
		if strings.HasSuffix(f, "Test.php") {
			tests = append(tests, f)
			continue
		}
		fqcn := ""
		for _, e := range entries {
			if strings.HasPrefix(f, e.dir) && strings.HasSuffix(f, ".php") {
				fqcn = e.prefix + strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(f, e.dir), ".php"), "/", `\`)
				break
			}
		}
		found := false
		if fqcn != "" {
			short := path.Base(strings.TrimSuffix(f, ".php"))
			for _, t := range phpTests {
				src, err := readFile(root, t)
				if err != nil {
					return nil, nil, err
				}
				if path.Base(t) == short+"Test.php" || strings.Contains(src, fqcn) {
					tests, found = append(tests, t), true
				}
			}
		}
		if !found {
			uncovered = append(uncovered, f)
		}
	}
	return uniq(tests), uniq(uncovered), nil
}

func (PHPUnit) Run(ctx context.Context, root string, spec core.VerifyAdapterSpec, tests []string, full bool) (core.TestResult, error) {
	return runCmd(ctx, root, spec, tests, full)
}
