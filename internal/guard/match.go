package guard

import (
	"sort"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/globs"
)

// word is one statically analysed shell word. dyn means the value depends on
// expansion at run time (variable, substitution, brace list, $'..'); glob means
// it contains an unquoted wildcard.
type word struct {
	s    string
	dyn  bool
	glob bool
}

// globWord matches pat (with * and ?) against s; * matches any run of characters.
func globWord(pat, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pat) && (pat[px] == '?' || pat[px] == s[sx]) && pat[px] != '*':
			px++
			sx++
		case px < len(pat) && pat[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pat) && pat[px] == '*' {
		px++
	}
	return px == len(pat)
}

func isShortCluster(w string) bool {
	if len(w) < 2 || w[0] != '-' || w[1] == '-' {
		return false
	}
	for _, c := range w[1:] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// canon splits short-flag clusters (-rf => -f -r) and sorts each contiguous run
// of them, so `rm -fr /`, `rm -r -f /` and `rm -rf /` compare equal. Dynamic
// words are barriers and stay as they are.
func canon(words []word) ([]string, []bool) {
	out := make([]string, 0, len(words))
	dyn := make([]bool, 0, len(words))
	var run []string
	flush := func() {
		sort.Strings(run)
		for _, f := range run {
			out, dyn = append(out, f), append(dyn, false)
		}
		run = run[:0]
	}
	for _, w := range words {
		if !w.dyn && isShortCluster(w.s) {
			seen := map[string]bool{}
			for _, c := range w.s[1:] {
				f := "-" + string(c)
				if !seen[f] {
					seen[f] = true
					run = append(run, f)
				}
			}
			continue
		}
		flush()
		out, dyn = append(out, w.s), append(dyn, w.dyn)
	}
	flush()
	return out, dyn
}

// matchCommand reports whether argv matches the policy pattern. Patterns are
// whitespace-separated words; a word is a glob; a final word ending in * also
// swallows every remaining argument ("php bin/phpunit*"); a lone * in the middle
// matches any run of words. A dynamic argv word may stand for anything.
func matchCommand(pattern string, argv []word, strict bool) bool {
	pws := make([]word, 0, 8)
	for _, f := range strings.Fields(pattern) {
		pws = append(pws, word{s: f})
	}
	pw, _ := canon(pws)
	if len(pw) == 0 || len(argv) == 0 {
		return false
	}
	av, dyn := canon(argv)
	return matchWords(pw, av, dyn, strict) || (!strict && matchFlagsAnywhere(pw, av, dyn))
}

func matchWords(pw, av []string, dyn []bool, strict bool) bool {
	if len(pw) == 0 {
		return len(av) == 0
	}
	p := pw[0]
	last := len(pw) == 1
	if p == "*" {
		if last {
			return true
		}
		for k := 0; k <= len(av); k++ {
			if matchWords(pw[1:], av[k:], dyn[k:], strict) {
				return true
			}
		}
		return false
	}
	if len(av) == 0 {
		return false
	}
	if !strict && skipOption(pw, av, dyn) {
		return true
	}
	if last && strict && strings.HasSuffix(p, "*") {
		// allow patterns: `cmd*` is `cmd` then end-of-word, never `cmd.evil`
		return dyn[0] || globWord(strings.TrimSuffix(p, "*"), av[0])
	}
	if !dyn[0] && !globWord(p, av[0]) {
		return false
	}
	if last && strings.HasSuffix(p, "*") {
		return true
	}
	return matchWords(pw[1:], av[1:], dyn[1:], strict)
}

// skipOption (deny/ask only): an option token, and optionally one value after
// it, may sit between the words of a pattern (`php -d x=1 bin/console ...`).
func skipOption(pw, av []string, dyn []bool) bool {
	if dyn[0] || !strings.HasPrefix(av[0], "-") || strings.HasPrefix(pw[0], "-") {
		return false
	}
	return matchWords(pw, av[1:], dyn[1:], false) || (len(av) > 1 && matchWords(pw, av[2:], dyn[2:], false))
}

// matchFlagsAnywhere handles `git push --force*` against `git push origin --force`:
// a pattern whose trailing words are all flags matches when its leading words
// match the start of argv and every flag appears anywhere later.
func matchFlagsAnywhere(pw, av []string, dyn []bool) bool {
	i := len(pw)
	for i > 0 && strings.HasPrefix(pw[i-1], "-") {
		i--
	}
	if i == len(pw) || i == 0 || len(av) < i {
		return false
	}
	for k := 0; k < i; k++ {
		if (!dyn[k] && !globWord(pw[k], av[k])) || strings.Contains(pw[k], "*") {
			return false
		}
	}
	for _, f := range pw[i:] {
		found := false
		for k := i; k < len(av) && !found; k++ {
			found = dyn[k] || globWord(f, av[k]) || (f == "--force*" && av[k] == "-f")
		}
		if !found {
			return false
		}
	}
	return true
}

// matchPath delegates to internal/globs, the matcher shared with internal/policy,
// so a narrowing the differ calls LOOSEN is enforced the same way here.
func matchPath(pat, rel string) bool { return globs.Match(pat, rel) }
