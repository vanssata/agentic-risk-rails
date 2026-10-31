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
	stopWords = map[string]bool{"a": true, "an": true, "the": true, "is": true, "are": true, "was": true, "were": true,
		"be": true, "been": true, "of": true, "to": true, "in": true, "on": true, "for": true, "by": true, "with": true,
		"and": true, "or": true, "it": true, "its": true, "this": true, "that": true, "as": true, "at": true, "from": true}
	lineSuffix = regexp.MustCompile(`:\d+(-\d+)?$`)
	numRe      = regexp.MustCompile(`\d+(?:\.\d+)*[a-z%]*`)
	apostrophe = strings.NewReplacer("'", "", "\u2019", "", "\u2018", "")
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

// shape splits a claim into content words (no stop words, negations or numbers),
// a whole-word negation flag and the ordered number sequence.
func shape(claim string) (words map[string]bool, neg bool, nums string) {
	words = map[string]bool{}
	c := apostrophe.Replace(strings.ToLower(claim))
	nums = strings.Join(numRe.FindAllString(c, -1), ",")
	for _, w := range strings.FieldsFunc(c, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
	}) {
		w = strings.Trim(w, "-")
		switch {
		case w == "" || stopWords[w]:
		case negations[w]:
			neg = true
		case strings.IndexFunc(w, unicode.IsDigit) >= 0:
		default:
			words[w] = true
		}
	}
	return words, neg, nums
}

func wordKey(w map[string]bool) string {
	ks := make([]string, 0, len(w))
	for k := range w {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, " ")
}

func inter(a, b map[string]bool) int {
	n := 0
	for w := range a {
		if b[w] {
			n++
		}
	}
	return n
}

// similar: Jaccard >= 0.8, or two claims of >= 2 words that differ by one word
// (short claims such as "enabled by default" vs "disabled by default").
func similar(a, b map[string]bool) bool {
	n := inter(a, b)
	if u := len(a) + len(b) - n; u > 0 && float64(n)/float64(u) >= SimilarityThreshold {
		return true
	}
	return len(a) == len(b) && len(a) >= 2 && n == len(a)-1
}

type shaped struct {
	f     Fact
	words map[string]bool
	key   string
	neg   bool
	nums  string
}

// Merge unions reports in the order given. Two facts merge (sources joined) only
// when content words, polarity and number sequence are all identical. Any other
// pair that is similar (see similar) is never merged and becomes a Conflict.
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
			w, neg, nums := shape(f.Claim)
			key := wordKey(w)
			var hit *shaped
			for _, u := range uniq {
				if u.key == key && u.neg == neg && u.nums == nums {
					hit = u
					break
				}
			}
			if hit == nil {
				uniq = append(uniq, &shaped{f: Fact{f.Claim, append([]string(nil), f.Sources...), f.Tag}, words: w, key: key, neg: neg, nums: nums})
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
			if similar(a.words, b.words) {
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

// MergeBrief renders the merge brief for the strong model, at most maxTokens
// (the COST line and omitted counters are always kept). Every list is capped with
// an "<NAME>-OMITTED: n" counter: first FACTS ([V] listed before [U]) are cut,
// then the other lists.
func MergeBrief(m Merged, maxTokens int) string {
	facts := append([]Fact(nil), m.Facts...)
	sort.SliceStable(facts, func(i, j int) bool { return facts[i].Tag == "[V]" && facts[j].Tag != "[V]" })
	m.Facts = facts
	other := max(len(m.Conflicts), len(m.Gaps), len(m.Touches), len(m.Steal), len(m.Avoid))
	fits := func(kf, ko int) bool { return EstimateTokens(renderMerged(m, kf, ko)) <= maxTokens }
	kf, ko := len(facts), other
	if !fits(kf, ko) {
		// largest number of facts that fits with all other lists; else no facts and fewer other items
		kf = max(sort.Search(len(facts)+1, func(i int) bool { return !fits(i, other) })-1, 0)
		if !fits(kf, other) {
			ko = max(sort.Search(other+1, func(i int) bool { return !fits(0, i) })-1, 0)
		}
	}
	return renderMerged(m, kf, ko)
}

func renderMerged(m Merged, kf, ko int) string {
	var b strings.Builder
	list := func(title string, items []string, keep int) {
		if len(items) == 0 {
			return
		}
		keep = min(keep, len(items))
		if keep > 0 {
			b.WriteString(title + ":\n")
		}
		for _, it := range items[:keep] {
			b.WriteString("- " + it + "\n")
		}
		if keep < len(items) {
			fmt.Fprintf(&b, "%s-OMITTED: %d\n", strings.Fields(title)[0], len(items)-keep)
		}
	}
	var cs, fs []string
	for _, c := range m.Conflicts {
		cs = append(cs, "A: "+c.A.String()+"\n  B: "+c.B.String())
	}
	for _, f := range m.Facts {
		fs = append(fs, f.String())
	}
	list("CONFLICT (phase 2 candidates)", cs, ko)
	list("FACTS", fs, kf)
	list("GAPS (phase 2 candidates)", m.Gaps, ko)
	list("TOUCHES", m.Touches, ko)
	list("STEAL", m.Steal, ko)
	list("AVOID", m.Avoid, ko)
	fmt.Fprintf(&b, "COST: tokens=%d calls=%d\n", m.Tokens, m.Calls)
	return b.String()
}
