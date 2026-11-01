package guard

import (
	"path"
	"regexp"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// strongOutTokens name an output target by themselves; weakOutTokens do so when
// the value looks like a path (log/coverage/report files of test runners).
var (
	strongOutTokens = opts("output", "out", "outfile", "output-file", "output-dir", "output-directory")
	weakOutTokens   = opts("log", "junit", "coverage", "report", "dump", "cache", "testdox", "result")
)

// outputFlag: a long option whose value is a file the command writes
// (`git diff --output=f`, `phpunit --log-junit f`, `--coverage-html d`).
// Such values get the full write rules, not just the read rules.
func outputFlag(name, val string, argv []word, call core.ToolCall, gc core.GuardContext) bool {
	n, long := strings.CutPrefix(name, "--")
	if !long {
		return false
	}
	if strongOutTokens[n] {
		return true
	}
	if argv[0].s == "git" && len(n) >= 4 && len(n) <= 6 && "output"[:len(n)] == n {
		return true // git accepts unique prefixes: --outp=f
	}
	if !pathLike(val, call, gc) {
		return false
	}
	for _, t := range strings.Split(n, "-") {
		if weakOutTokens[t] {
			return true
		}
	}
	return false
}

// shortOutputOf: -o takes an output file for these commands (git: only the
// subcommands where it does, since `git ls-files -o` takes no value).
func shortOutputOf(argv []word) bool {
	if argv[0].s != "git" {
		return shortOutput[argv[0].s]
	}
	if len(argv) > 1 {
		switch argv[1].s {
		case "diff", "log", "show", "format-patch", "archive":
			return true
		}
	}
	return false
}

var (
	procExeRe   = regexp.MustCompile(`^/proc/[^/]+/exe$`)
	rrTaskInStr = regexp.MustCompile(`\brr\b.*\btask\b`)
)

// alwaysDenied extends core.AlwaysDeniedCommands to the ways an agent can reach
// `rr task` indirectly: any path to the binary, its own executable, `go run`,
// eval strings, xargs/parallel and alias bodies.
func alwaysDenied(f []word, xargs bool) (string, bool) {
	if len(f) == 0 || f[0].dyn {
		return "", false
	}
	for _, pat := range core.AlwaysDeniedCommands {
		g := append([]word{{s: path.Base(f[0].s)}}, f[1:]...)
		if matchCommand(pat, g, false) {
			return pat, true
		}
	}
	name := path.Base(f[0].s)
	switch {
	case procExeRe.MatchString(f[0].s):
		return "/proc/*/exe", true
	case name == "rr" && xargs:
		return "xargs rr", true
	case name == "go" && len(f) > 2 && f[1].s == "run":
		return anyArg(f[2:], "go run cmd/rr", func(s string) bool { return strings.HasSuffix(strings.TrimRight(s, "/"), "cmd/rr") })
	case name == "parallel":
		return anyArg(f[1:], "parallel rr", func(s string) bool { return path.Base(s) == "rr" })
	case name == "eval":
		return anyArg(f[1:], "eval rr task", rrTaskInStr.MatchString)
	case name == "alias":
		return anyArg(f[1:], "alias of rr task", aliasDenied)
	}
	return "", false
}

func anyArg(ws []word, rule string, bad func(string) bool) (string, bool) {
	for _, w := range ws {
		if bad(w.s) {
			return rule, true
		}
	}
	return "", false
}

// aliasDenied: an alias definition `x=body` whose body is an always-denied command.
func aliasDenied(def string) bool {
	_, body, ok := strings.Cut(def, "=")
	if !ok {
		return false
	}
	var g []word
	for _, s := range strings.Fields(body) {
		g = append(g, word{s: s})
	}
	_, bad := alwaysDenied(g, false)
	return bad
}
