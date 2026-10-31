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
	// Unreadable files exist but could not be read in full (binary, over the cap, symlink,
	// outside the root): they score upward. Deleted files are removed by the change
	// (caller: git diff --name-status); they are not "new".
	Unreadable map[string]bool
	Deleted    map[string]bool
	Spec       bool // a spec drives the task (programme trigger)
	Sessions   int  // sessions the task spans (programme trigger)
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

// scorer holds what every axis measurement needs.
type scorer struct {
	r                 core.RiskSpec
	in                Input
	tests             []string
	testsOnly, allNew bool
}

// Score measures the six axes and derives the mode.
func Score(pol core.Policy, in Input) core.Weight {
	s := scorer{r: pol.Risk, in: in, tests: pol.Risk.Axes[core.AxisCoverage].TestGlobs, testsOnly: len(in.Files) > 0, allNew: true}
	for _, f := range in.Files {
		if anyMatch(s.tests, f) == "" {
			s.testsOnly = false
		}
		if _, ok := in.Refs[f]; ok || in.Deleted[f] {
			s.allNew = false
		}
	}
	m := map[core.Axis]*measure{
		core.AxisScope: s.scope(), core.AxisBehaviour: s.behaviour(), core.AxisReversibility: s.reversibility(),
		core.AxisDomain: s.domain(), core.AxisNovelty: s.novelty(), core.AxisCoverage: s.coverage(),
	}
	if s.testsOnly {
		for _, a := range []core.Axis{core.AxisDomain, core.AxisNovelty} {
			if !m[a].ok {
				m[a].set(0, "tests only")
			}
		}
	}

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
		case !x.ok && s.r.Axes[a].Declared != nil && *s.r.Axes[a].Declared:
			x.v, x.why = 1, "UNKNOWN, neither measured nor declared"
		}
		w.Axes[a] = x.v
		w.Reasons = append(w.Reasons, fmt.Sprintf("%s=%d: %s", a, x.v, x.why))
	}
	if applyPolicyFileWeight(s.r, in, w.Axes) {
		w.Reasons = append(w.Reasons, policyFile+" changed: policy_file_weight applied")
	}
	w.Mode, w.Reasons = modeFor(pol, w.Axes, in, w.Reasons)
	w.Irreversible = irreversible(pol.Risk, w.Axes)
	return w
}

// scope: references and hot_paths.
func (s scorer) scope() *measure {
	lo, hi := 0, 5
	if b := s.r.Axes[core.AxisScope].Bands; len(b) >= 2 {
		lo, hi = b[0], b[1]
	}
	m := &measure{}
	m.set(0, "no references")
	for _, f := range s.in.Files {
		if p := anyMatch(s.r.HotPaths, f); p != "" {
			m.set(2, f+" matches hot_paths "+p)
		} else if n, ok := s.in.Refs[f]; ok {
			v := 2
			if n <= lo {
				v = 0
			} else if n <= hi {
				v = 1
			}
			m.set(v, fmt.Sprintf("%s referenced from %d files", f, n))
		}
	}
	return m
}

// behaviour: keyword floor; 0 for tests-only or all-new; else the session's call.
func (s scorer) behaviour() *measure {
	m := &measure{}
	for _, kw := range s.r.Axes[core.AxisBehaviour].Keywords {
		rx := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(kw) + `\b`)
		if rx.MatchString(s.in.Goal) {
			m.set(1, fmt.Sprintf("keyword %q in the goal", kw))
		}
		for _, f := range s.in.Files {
			if rx.MatchString(s.in.Content[f]) {
				m.set(1, fmt.Sprintf("keyword %q in %s", kw, f))
			}
		}
	}
	for _, f := range s.in.Files {
		if s.in.Unreadable[f] || s.in.Deleted[f] {
			m.set(1, f+" is unreadable or deleted")
		}
	}
	if !m.ok && (s.testsOnly || s.allNew) {
		m.set(0, "tests only or every file is new")
	}
	return m
}

// reversibility: paths, then content of non-test needs_step/irreversible files.
func (s scorer) reversibility() *measure {
	rev := s.r.Reversibility
	m := &measure{}
	m.set(0, "git revert returns everything")
	for _, f := range s.in.Files {
		irr, step := anyMatch(rev.Irreversible, f), anyMatch(rev.NeedsStep, f)
		if irr != "" {
			m.set(2, f+" matches irreversible "+irr)
		} else if step != "" {
			m.set(1, f+" matches needs_step "+step)
		}
		if (irr != "" || step != "") && anyMatch(s.tests, f) == "" {
			if s.in.Unreadable[f] {
				m.set(2, f+" is unreadable")
			} else if p := contentHit(rev.IrreversibleContent, s.in.Content[f]); p != "" {
				m.set(2, fmt.Sprintf("%s contains %q", f, p))
			}
		}
	}
	return m
}

// domain: paths. customer_visible is 1, any other class is 2.
func (s scorer) domain() *measure {
	classes := make([]string, 0, len(s.r.Domain))
	for c := range s.r.Domain {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	m := &measure{}
	for _, f := range s.in.Files {
		for _, c := range classes {
			if p := anyMatch(s.r.Domain[c], f); p != "" {
				v := 2
				if c == "customer_visible" {
					v = 1
				}
				m.set(v, fmt.Sprintf("%s is %s (%s)", f, c, p))
			}
		}
	}
	return m
}

// novelty: a dependency manifest among the files.
func (s scorer) novelty() *measure {
	m := &measure{}
	if floor := s.r.Axes[core.AxisNovelty].ManifestFloor; floor != nil {
		for _, f := range s.in.Files {
			if anyMatch(manifests, path.Base(f)) != "" {
				m.set(*floor, f+" is a dependency manifest")
			}
		}
	}
	return m
}

// coverage: a code file is covered when some test file's name contains its identifier.
func (s scorer) coverage() *measure {
	var testNames []string
	for _, t := range append(append([]string{}, s.in.Tree...), s.in.Files...) {
		if anyMatch(s.tests, t) != "" {
			testNames = append(testNames, path.Base(t))
		}
	}
	code, covered := 0, 0
	for _, f := range s.in.Files {
		if !codeExt[path.Ext(f)] || anyMatch(s.tests, f) != "" {
			continue
		}
		code++
		word := regexp.MustCompile(`(?:^|[^A-Za-z0-9])` + regexp.QuoteMeta(ident(f)) + `(?:$|[^A-Za-z0-9]|[Tt]est|[Ss]pec)`)
		for _, t := range testNames {
			if word.MatchString(t) {
				covered++
				break
			}
		}
	}
	v := 0
	if covered < code {
		v = 1
		if covered == 0 {
			v = 2
		}
	}
	m := &measure{}
	m.set(v, fmt.Sprintf("%d of %d code files have a test", covered, code))
	return m
}

// applyPolicyFileWeight raises axes to policy_file_weight when the policy file is among the files.
func applyPolicyFileWeight(r core.RiskSpec, in Input, axes map[core.Axis]int) bool {
	for _, f := range in.Files {
		if path.Base(f) == policyFile {
			for a, v := range r.PolicyFileWeight {
				axes[a] = max(axes[a], v)
			}
			return true
		}
	}
	return false
}

func contentHit(patterns []string, text string) string {
	for _, p := range patterns {
		rx, err := regexp.Compile("(?i)" + p)
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
		if floorHit(h, axes) {
			label := string(h.Axis)
			if len(h.Both) > 0 {
				label = fmt.Sprint(h.Both)
			}
			why := fmt.Sprintf("hard floor %s>=%d -> %s", label, h.Value, h.Mode)
			if h.Review != "" {
				why += " (review: " + h.Review + ")"
			}
			bump(h.Mode, why)
		}
	}
	for _, t := range r.Modes[core.ModeProgramme].Trigger {
		fired := true // an unknown trigger errs upward
		mm := filesOver.FindStringSubmatch(t)
		switch {
		case mm != nil:
			n, _ := strconv.Atoi(mm[1])
			fired = len(in.Files) > n
		case t == "spec":
			fired = in.Spec
		case t == ">1 session":
			fired = in.Sessions > 1
		}
		if fired {
			bump(core.ModeProgramme, "programme trigger "+strconv.Quote(t))
		}
	}
	return mode, reasons
}

func floorHit(h core.HardFloor, axes map[core.Axis]int) bool {
	hit := h.Axis != "" && axes[h.Axis] >= h.Value
	if len(h.Both) > 0 {
		hit = true
		for _, a := range h.Both {
			hit = hit && axes[a] >= h.Value
		}
	}
	return hit
}

// irreversible reports whether a full_irreversible hard floor holds.
func irreversible(r core.RiskSpec, axes map[core.Axis]int) bool {
	for _, h := range r.HardFloors {
		if h.Mode == core.ModeFullIrreversible && floorHit(h, axes) {
			return true
		}
	}
	return false
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
	if applyPolicyFileWeight(pol.Risk, in, out.Axes) {
		out.Reasons = append(out.Reasons, policyFile+" changed: policy_file_weight applied")
	}
	out.Mode, out.Reasons = modeFor(pol, out.Axes, in, out.Reasons)
	out.Irreversible = prev.Irreversible || irreversible(pol.Risk, out.Axes)
	if prev.Mode.Rank() > out.Mode.Rank() {
		out.Mode = prev.Mode
	}
	return out
}
