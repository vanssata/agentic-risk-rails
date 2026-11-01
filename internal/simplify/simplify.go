// Package simplify is the deterministic preflight of `rr simplify` (DES 9.3):
// duplicate detection (jscpd) and project rules (ast-grep) over the changed
// files. The LLM pass lives in the rr-simplify skill, never here.
package simplify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/vanssata/agentic-risk-rails/internal/hostexec"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Marker in a file excludes it from the simplify pass.
const Marker = "simplify-ignore"

type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

type ToolReport struct {
	Name     string    `json:"name"`
	Status   string    `json:"status"` // ok | skipped: ... | error: ...
	Findings []Finding `json:"findings"`
}

type Report struct {
	Files   []string     `json:"files"`   // files for the BALANCED pass
	Ignored []string     `json:"ignored"` // files carrying the marker
	Tools   []ToolReport `json:"tools"`
}

// Run reports on files (repo-relative). A missing tool is a skipped entry, not an error.
func Run(ctx context.Context, root string, files []string) Report {
	r := Report{Files: []string{}, Ignored: []string{}}
	for _, f := range files {
		if strings.HasPrefix(f, "-") {
			continue // never a flag for a tool
		}
		if b, err := os.ReadFile(filepath.Join(root, f)); err == nil && bytes.Contains(b, []byte(Marker)) {
			r.Ignored = append(r.Ignored, f)
		} else {
			r.Files = append(r.Files, f)
		}
	}
	r.Tools = []ToolReport{jscpd(ctx, root, r.Files), astGrep(ctx, root, r.Files)}
	return r
}

// hostCmd finds name only in safePath(root) and gives it an allowlisted environment.
func hostCmd(ctx context.Context, root, name string, args ...string) (*exec.Cmd, bool) {
	dirs := hostexec.SafePath(root)
	p, found := hostexec.Lookup(dirs, name)
	if !found {
		return nil, false
	}
	c := exec.CommandContext(ctx, p, args...)
	c.Dir = root
	c.Env = []string{"PATH=" + strings.Join(dirs, string(filepath.ListSeparator))}
	for _, k := range []string{"HOME", "LANG", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	return c, true
}

func skipped(name, why string) ToolReport {
	return ToolReport{Name: name, Status: "skipped: " + why, Findings: []Finding{}}
}

func failed(name string, err error) ToolReport {
	return ToolReport{Name: name, Status: "error: " + err.Error(), Findings: []Finding{}}
}

// jscpd scans the repo and keeps clones that touch a changed file.
func jscpd(ctx context.Context, root string, files []string) ToolReport {
	const name = "jscpd"
	out, err := os.MkdirTemp("", "rr-jscpd-")
	if err != nil {
		return failed(name, err)
	}
	defer os.RemoveAll(out)
	cmd, ok := hostCmd(ctx, root, name, "--silent", "--reporters", "json", "--output", out, ".")
	if !ok {
		return skipped(name, "not installed")
	}
	_ = cmd.Run() // may exit non-zero on thresholds; the report decides
	b, err := os.ReadFile(filepath.Join(out, "jscpd-report.json"))
	if err != nil {
		return failed(name, fmt.Errorf("no report: %w", err))
	}
	var rep struct {
		Duplicates []struct {
			Lines     int `json:"lines"`
			FirstFile struct {
				Name  string `json:"name"`
				Start int    `json:"start"`
			} `json:"firstFile"`
			SecondFile struct {
				Name  string `json:"name"`
				Start int    `json:"start"`
			} `json:"secondFile"`
		} `json:"duplicates"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		return failed(name, err)
	}
	tr := ToolReport{Name: name, Status: "ok", Findings: []Finding{}}
	for _, d := range rep.Duplicates {
		a, c := filepath.ToSlash(d.FirstFile.Name), filepath.ToSlash(d.SecondFile.Name)
		if slices.Contains(files, a) || slices.Contains(files, c) {
			tr.Findings = append(tr.Findings, Finding{File: a, Line: d.FirstFile.Start,
				Message: fmt.Sprintf("%d duplicated lines with %s:%d", d.Lines, c, d.SecondFile.Start)})
		}
	}
	return tr
}

// astGrep runs the project's own rules; without sgconfig.yml there are none.
func astGrep(ctx context.Context, root string, files []string) ToolReport {
	const name = "ast-grep"
	cfg, err := os.ReadFile(filepath.Join(root, "sgconfig.yml"))
	if err != nil {
		return skipped(name, "no sgconfig.yml")
	}
	if bytes.Contains(cfg, []byte("customLanguages")) || bytes.Contains(cfg, []byte("libraryPath")) {
		return skipped(name, "custom languages load code")
	}
	if len(files) == 0 {
		return ToolReport{Name: name, Status: "ok", Findings: []Finding{}}
	}
	cmd, ok := hostCmd(ctx, root, name, append([]string{"scan", "--json=stream", "--"}, files...)...)
	if !ok {
		return skipped(name, "not installed")
	}
	b, err := cmd.Output() // exit 1 is possible when error-severity rules match
	if len(b) == 0 && err != nil {
		return failed(name, err)
	}
	tr := ToolReport{Name: name, Status: "ok", Findings: []Finding{}}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m struct {
			File    string `json:"file"`
			RuleID  string `json:"ruleId"`
			Message string `json:"message"`
			Range   struct {
				Start struct {
					Line int `json:"line"`
				} `json:"start"`
			} `json:"range"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		tr.Findings = append(tr.Findings, Finding{File: m.File, Line: m.Range.Start.Line + 1,
			Message: strings.TrimSpace(m.RuleID + ": " + m.Message)})
	}
	return tr
}
