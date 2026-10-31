package research

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// SimilarityThreshold is the Jaccard bound of DES §5.4.
const SimilarityThreshold = 0.8

// Conflict is a pair of near-identical claims that differ in polarity or numbers.
type Conflict struct{ A, B Fact }

// Merged is the deterministic union of scout reports.
type Merged struct {
	Facts     []Fact
	Conflicts []Conflict
	Gaps      []string // phase-2 candidates
	Touches   []string
	Steal     []string
	Avoid     []string
	Tokens    int64
	Calls     int
}

var (
	negations = map[string]bool{"not": true, "no": true, "never": true, "without": true, "cannot": true,
		"cant": true, "dont": true, "doesnt": true, "isnt": true, "wont": true, "не": true, "без": true, "никога": true}
	lineSuffix = regexp.MustCompile(`:\d+(-\d+)?$`)
)

// NormSource lowercases a source and drops scheme, fragment, trailing slash and :line.
func NormSource(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	s = lineSuffix.ReplaceAllString(s, "")
	return strings.TrimRight(s, "/")
}

// shape splits a claim into topic words, negation flag and number set.
func shape(claim string) (topic map[string]bool, neg bool, nums string) {
	topic = map[string]bool{}
	var ns []string
	words := strings.FieldsFunc(strings.ToLower(strings.ReplaceAll(claim, "'", "")), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, w := range words {
		switch {
		case negations[w]:
			neg = true
		case strings.IndexFunc(w, unicode.IsDigit) >= 0:
			ns = append(ns, w)
		default:
			topic[w] = true
		}
	}
	sort.Strings(ns)
	return topic, neg, strings.Join(ns, ",")
}

func jaccard(a, b map[string]bool) float64 {
	inter := 0
	for w := range a {
		if b[w] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

type shaped struct {
	f     Fact
	topic map[string]bool
	neg   bool
	nums  string
}

// Merge unions reports in the order given. Facts with topic similarity >= 0.8
// (negations and numbers excluded from the topic) and equal polarity and numbers
// are one fact with the sources joined; equal topic but different polarity or
// numbers are never merged and become Conflicts.
func Merge(reports []Report) Merged {
	var m Merged
	var uniq []*shaped
	gaps, touches, steal, avoid := set{}, set{}, set{}, set{}
	for _, r := range reports {
		m.Tokens += r.Tokens
		m.Calls += r.Calls
		gaps.add(&m.Gaps, r.Gaps)
		touches.add(&m.Touches, r.Touches)
		steal.add(&m.Steal, r.Steal)
		avoid.add(&m.Avoid, r.Avoid)
		for _, f := range r.Facts {
			t, neg, nums := shape(f.Claim)
			var hit *shaped
			for _, u := range uniq {
				if u.neg == neg && u.nums == nums && jaccard(u.topic, t) >= SimilarityThreshold {
					hit = u
					break
				}
			}
			if hit == nil {
				uniq = append(uniq, &shaped{f: Fact{f.Claim, append([]string(nil), f.Sources...), f.Tag}, topic: t, neg: neg, nums: nums})
				continue
			}
			hit.f.Sources = unionSources(hit.f.Sources, f.Sources)
			if f.Tag == "[V]" {
				hit.f.Tag = "[V]"
			}
		}
	}
	inConflict := map[*shaped]bool{}
	for i, a := range uniq {
		for _, b := range uniq[i+1:] {
			if (a.neg != b.neg || a.nums != b.nums) && jaccard(a.topic, b.topic) >= SimilarityThreshold {
				m.Conflicts = append(m.Conflicts, Conflict{a.f, b.f})
				inConflict[a], inConflict[b] = true, true
			}
		}
	}
	for _, u := range uniq {
		if !inConflict[u] {
			m.Facts = append(m.Facts, u.f)
		}
	}
	return m
}

type set map[string]bool

func (s set) add(dst *[]string, items []string) {
	for _, it := range items {
		if !s[it] {
			s[it] = true
			*dst = append(*dst, it)
		}
	}
}

func unionSources(a, b []string) []string {
	for _, s := range b {
		dup := false
		for _, x := range a {
			if NormSource(x) == NormSource(s) {
				dup = true
			}
		}
		if !dup {
			a = append(a, s)
		}
	}
	return a
}

func (f Fact) String() string {
	return fmt.Sprintf("%s | %s | %s", f.Claim, strings.Join(f.Sources, " ; "), f.Tag)
}

// MergeBrief renders the merge brief for the strong model, at most maxTokens.
// Facts are listed [V] before [U]; the tail is dropped (and counted) to fit.
func MergeBrief(m Merged, maxTokens int) (string, error) {
	facts := append([]Fact(nil), m.Facts...)
	sort.SliceStable(facts, func(i, j int) bool { return facts[i].Tag == "[V]" && facts[j].Tag != "[V]" })
	for omitted := 0; omitted <= len(facts); omitted++ {
		s := renderMerged(m, facts[:len(facts)-omitted], omitted)
		if EstimateTokens(s) <= maxTokens {
			return s, nil
		}
	}
	return "", fmt.Errorf("research: merge brief exceeds %d tokens without any FACTS", maxTokens)
}

func renderMerged(m Merged, facts []Fact, omitted int) string {
	var b strings.Builder
	list := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		b.WriteString(title + ":\n")
		for _, it := range items {
			b.WriteString("- " + it + "\n")
		}
	}
	if len(m.Conflicts) > 0 {
		b.WriteString("CONFLICT (phase 2 candidates):\n")
		for _, c := range m.Conflicts {
			b.WriteString("- A: " + c.A.String() + "\n  B: " + c.B.String() + "\n")
		}
	}
	var fs []string
	for _, f := range facts {
		fs = append(fs, f.String())
	}
	list("FACTS", fs)
	if omitted > 0 {
		fmt.Fprintf(&b, "FACTS-OMITTED: %d (brief limit)\n", omitted)
	}
	list("GAPS (phase 2 candidates)", m.Gaps)
	list("TOUCHES", m.Touches)
	list("STEAL", m.Steal)
	list("AVOID", m.Avoid)
	fmt.Fprintf(&b, "COST: tokens=%d calls=%d\n", m.Tokens, m.Calls)
	return b.String()
}
