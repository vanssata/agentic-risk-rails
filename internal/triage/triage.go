// Package triage scores a task on six axes and picks its mode (DES 3.2, 2.3).
// Everything here is a pure function of Input and core.Policy.
package triage

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
)

// Input is everything triage knows about a task.
type Input struct {
	Files    []string          // repo-relative files the task touches (or the diff)
	Goal     string            // free text, scanned for behaviour keywords
	Declared map[core.Axis]int // session declarations; they only raise a measurement
	Refs     map[string]int    // reference count of each EXISTING file; a file absent here is new
	Tree     []string          // every repo file, to look up tests
	Content  map[string]string // text of files, or added diff lines (rescore)
	Spec     bool              // a spec drives the task (programme trigger)
	Sessions int               // sessions the task spans (programme trigger)
}

const policyFile = "riskrails.yaml"

var (
	codeExt   = map[string]bool{".php": true, ".py": true, ".js": true, ".ts": true, ".go": true, ".sh": true, ".java": true, ".rb": true, ".rs": true}
	manifests = []string{"composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"go.mod", "go.sum", "requirements*.txt", "pyproject.toml", "Gemfile", "Gemfile.lock", "Cargo.toml", "Cargo.lock"}
	filesOver = regexp.MustCompile(`^files\s*>\s*(\d+)$`)
)

func anyMatch(patterns []string, f string) string {
	for _, p := range patterns {
		if globs.Match(p, f) {
			return p
		}
	}
	return ""
}

func ident(f string) string {
	b := path.Base(f)
	if strings.HasPrefix(b, ".") {
		return b
	}
	return strings.SplitN(b, ".", 2)[0]
}

type measure struct {
	v   int
	why string
	ok  bool // measured; false = only the session can say
}

func (m *measure) set(v int, why string) {
	if !m.ok || v > m.v {
		m.v, m.why = v, why
	}
	m.ok = true
}

// Score measures the six axes and derives the mode.
func Score(pol core.Policy, in Input) core.Weight {
	r := pol.Risk
	tests := r.Axes[core.AxisCoverage].TestGlobs
	testsOnly := len(in.Files) > 0
	allNew := true
	for _, f := range in.Files {
		if anyMatch(tests, f) == "" {
			testsOnly = false
		}
		if _, ok := in.Refs[f]; ok {
			allNew = false
		}
	}
	m := map[core.Axis]*measure{}
	for _, a := range core.Axes {
		m[a] = &measure{}
	}

	// scope: references and hot_paths
	lo, hi := 0, 5
	if b := r.Axes[core.AxisScope].Bands; len(b) >= 2 {
		lo, hi = b[0], b[1]
	}
	m[core.AxisScope].set(0, "no references")
	for _, f := range in.Files {
		if p := anyMatch(r.HotPaths, f); p != "" {
			m[core.AxisScope].set(2, f+" matches hot_paths "+p)
		} else if n, ok := in.Refs[f]; ok {
			v := 2
			if n <= lo {
				v = 0
			} else if n <= hi {
				v = 1
			}
			m[core.AxisScope].set(v, fmt.Sprintf("%s referenced from %d files", f, n))
		}
	}

	// behaviour: keyword floor; 0 for tests-only or all-new; else the session's call
	for _, kw := range r.Axes[core.AxisBehaviour].Keywords {
		rx := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(kw) + `\b`)
		if rx.MatchString(in.Goal) {
			m[core.AxisBehaviour].set(1, fmt.Sprintf("keyword %q in the goal", kw))
		}
		for _, f := range in.Files {
			if rx.MatchString(in.Content[f]) {
				m[core.AxisBehaviour].set(1, fmt.Sprintf("keyword %q in %s", kw, f))
			}
		}
	}
	if !m[core.AxisBehaviour].ok && (testsOnly || allNew) {
		m[core.AxisBehaviour].set(0, "tests only or every file is new")
	}

	// reversibility: paths, then content of non-test needs_step/irreversible files
	rev := r.Reversibility
	m[core.AxisReversibility].set(0, "git revert returns everything")
	for _, f := range in.Files {
		irr, step := anyMatch(rev.Irreversible, f), anyMatch(rev.NeedsStep, f)
		if irr != "" {
			m[core.AxisReversibility].set(2, f+" matches irreversible "+irr)
		} else if step != "" {
			m[core.AxisReversibility].set(1, f+" matches needs_step "+step)
		}
		if (irr != "" || step != "") && anyMatch(tests, f) == "" {
			if p := contentHit(rev.IrreversibleContent, in.Content[f]); p != "" {
				m[core.AxisReversibility].set(2, fmt.Sprintf("%s contains %q", f, p))
			}
		}
	}

	// domain: paths. customer_visible is 1, any other class is 2
	classes := make([]string, 0, len(r.Domain))
	for c := range r.Domain {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, f := range in.Files {
		for _, c := range classes {
			if p := anyMatch(r.Domain[c], f); p != "" {
				v := 2
				if c == "customer_visible" {
					v = 1
				}
				m[core.AxisDomain].set(v, fmt.Sprintf("%s is %s (%s)", f, c, p))
			}
		}
	}

	// novelty: a dependency manifest among the files
	if floor := r.Axes[core.AxisNovelty].ManifestFloor; floor != nil {
		for _, f := range in.Files {
			if anyMatch(manifests, path.Base(f)) != "" {
				m[core.AxisNovelty].set(*floor, f+" is a dependency manifest")
			}
		}
	}
	if testsOnly {
		for _, a := range []core.Axis{core.AxisDomain, core.AxisNovelty} {
			if !m[a].ok {
				m[a].set(0, "tests only")
			}
		}
	}

	// coverage: a code file is covered when some test file's name contains its identifier
	var testNames []string
	for _, t := range append(append([]string{}, in.Tree...), in.Files...) {
		if anyMatch(tests, t) != "" {
			testNames = append(testNames, path.Base(t))
		}
	}
	code, covered := 0, 0
	for _, f := range in.Files {
		if !codeExt[path.Ext(f)] || anyMatch(tests, f) != "" {
			continue
		}
		code++
		for _, t := range testNames {
			if strings.Contains(t, ident(f)) {
				covered++
				break
			}
		}
	}
	cov := 0
	if covered < code {
		cov = 1
		if covered == 0 {
			cov = 2
		}
	}
	m[core.AxisCoverage].set(cov, fmt.Sprintf("%d of %d code files have a test", covered, code))

	w := core.Weight{Axes: map[core.Axis]int{}, Measured: true}
	for _, a := range core.Axes {
		x := m[a]
		d, declared := in.Declared[a]
		d = max(0, min(2, d))
		switch {
		case x.ok && declared && d > x.v:
			x.v, x.why = d, "declared"
		case !x.ok && declared:
			x.v, x.why = d, "declared"
		case !x.ok && r.Axes[a].Declared != nil && *r.Axes[a].Declared:
			x.v, x.why = 1, "UNKNOWN, neither measured nor declared"
		}
		w.Axes[a] = x.v
		w.Reasons = append(w.Reasons, fmt.Sprintf("%s=%d: %s", a, x.v, x.why))
	}
	for _, f := range in.Files {
		if path.Base(f) == policyFile {
			for a, v := range r.PolicyFileWeight {
				w.Axes[a] = max(w.Axes[a], v)
			}
			w.Reasons = append(w.Reasons, policyFile+" changed: policy_file_weight applied")
			break
		}
	}
	w.Mode, w.Reasons = modeFor(pol, w.Axes, in, w.Reasons)
	return w
}

func contentHit(patterns []string, text string) string {
	for _, p := range patterns {
		rx, err := regexp.Compile(p)
		if err != nil || rx.MatchString(text) { // an unreadable pattern errs upward
			return p
		}
	}
	return ""
}

// modeFor maps axes to a mode: W band, hard floors, programme triggers; the highest wins.
func modeFor(pol core.Policy, axes map[core.Axis]int, in Input, reasons []string) (core.Mode, []string) {
	r := pol.Risk
	w := core.Weight{Axes: axes}.Total()
	lightMax, fullMin := 2, 8
	if p := r.Modes[core.ModeLight].Max; p != nil {
		lightMax = *p
	}
	if p := r.Modes[core.ModeFull].Min; p != nil {
		fullMin = *p
	}
	mode := core.ModeGuarded
	switch {
	case w <= lightMax:
		mode = core.ModeLight
	case w >= fullMin:
		mode = core.ModeFull
	}
	reasons = append(reasons, fmt.Sprintf("W=%d -> %s", w, mode))
	bump := func(m core.Mode, why string) {
		if m.Rank() > mode.Rank() {
			mode = m
		}
		reasons = append(reasons, why)
	}
	for _, h := range r.HardFloors {
		hit := h.Axis != "" && axes[h.Axis] >= h.Value
		if len(h.Both) > 0 {
			hit = true
			for _, a := range h.Both {
				hit = hit && axes[a] >= h.Value
			}
		}
		if hit {
			why := fmt.Sprintf("hard floor %s%v>=%d -> %s", h.Axis, h.Both, h.Value, h.Mode)
			if h.Review != "" {
				why += " (review: " + h.Review + ")"
			}
			bump(h.Mode, why)
		}
	}
	for _, t := range r.Modes[core.ModeProgramme].Trigger {
		var fired bool
		if mm := filesOver.FindStringSubmatch(t); mm != nil {
			n, _ := strconv.Atoi(mm[1])
			fired = len(in.Files) > n
		} else if t == "spec" {
			fired = in.Spec
		} else if t == ">1 session" {
			fired = in.Sessions > 1
		} else {
			fired = true // an unknown trigger errs upward
		}
		if fired {
			bump(core.ModeProgramme, "programme trigger "+strconv.Quote(t))
		}
	}
	return mode, reasons
}

// Rescore re-measures against the real diff and raises only the axes in
// risk.rescore.axes. The result never has a lower axis or mode than prev.
func Rescore(pol core.Policy, prev core.Weight, in Input) core.Weight {
	return raise(pol, prev, in, pol.Risk.Rescore.Axes)
}

// Amend re-measures all six axes (task start --amend); again only upward.
func Amend(pol core.Policy, prev core.Weight, in Input) core.Weight {
	return raise(pol, prev, in, core.Axes)
}

func raise(pol core.Policy, prev core.Weight, in Input, axes []core.Axis) core.Weight {
	cur := Score(pol, in)
	out := core.Weight{Axes: map[core.Axis]int{}, Measured: true, Reasons: append([]string{}, prev.Reasons...)}
	for a, v := range prev.Axes {
		out.Axes[a] = v
	}
	for _, a := range axes {
		if cur.Axes[a] > out.Axes[a] {
			out.Reasons = append(out.Reasons, fmt.Sprintf("rescore %s %d -> %d", a, out.Axes[a], cur.Axes[a]))
			out.Axes[a] = cur.Axes[a]
		}
	}
	out.Mode, out.Reasons = modeFor(pol, out.Axes, in, out.Reasons)
	if prev.Mode.Rank() > out.Mode.Rank() {
		out.Mode = prev.Mode
	}
	return out
}
