package guard

import (
	"regexp"
	"strings"
)

// Known read-only commands are allowed when no list mentions them (L0/L1
// only: at L2+ unlisted is deny). They get no exemption from the path rules:
// every argument is still checked, so `cat .env.local` stays denied. Deny and
// ask lists are evaluated first and always win.

var (
	plainReadOnly = opts("ls", "cat", "head", "tail", "less", "more", "wc", "cmp", "stat", "du", "df", "which", "type",
		"basename", "dirname", "realpath", "readlink", "id", "whoami", "uname", "diff", "cut", "tr")
	sedBadRe = regexp.MustCompile(`(?:^|[\s;{}!,0-9$])[rRwWeE](?:\s|$|;|\})|/[0-9gpiImM]*[rRwWeE][0-9gpiIemMwW]*(?:\s|$|;|\})`)
	// subcommands whose output goes to the terminal only
	gitReadSubs = opts("status", "log", "show", "diff", "rev-parse", "ls-files", "blame", "describe", "grep")
	gitBranchOK = opts("-a", "-r", "-v", "-vv", "-l", "--list", "--all", "--remotes", "--verbose", "--show-current", "--no-color", "--color")
	gitConfigRd = opts("--get", "--get-all", "--get-regexp", "--list", "-l", "--get-urlmatch", "--show-origin", "--show-scope")
)

func hasArg(args []word, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a.s == n {
				return true
			}
		}
	}
	return false
}

func hasArgPrefix(args []word, prefixes ...string) bool {
	for _, a := range args {
		for _, p := range prefixes {
			if strings.HasPrefix(a.s, p) {
				return true
			}
		}
	}
	return false
}

func positionals(args []word) []word {
	var out []word
	for _, a := range args {
		if !strings.HasPrefix(a.s, "-") || a.s == "-" {
			out = append(out, a)
		}
	}
	return out
}

// readOnlyRules decide per command from its arguments.
var readOnlyRules = map[string]func(args []word) bool{
	"uniq": func(a []word) bool { return len(positionals(a)) <= 1 },
	"file": func(a []word) bool { return !hasArg(a, "-C") },
	"tree": func(a []word) bool { return !hasArgPrefix(a, "-o") },
	"date": func(a []word) bool { return !hasArg(a, "-s", "--set") && !hasArgPrefix(a, "--set=") },
	"sort": func(a []word) bool {
		return !hasArgPrefix(a, "--output", "--compress-program") && !shortClusterHas(a, 'o')
	},
	"find": func(a []word) bool {
		return !hasArg(a, "-exec", "-execdir", "-ok", "-okdir", "-delete") && !hasArgPrefix(a, "-fprint", "-fls")
	},
	"grep":     func([]word) bool { return true },
	"egrep":    func([]word) bool { return true },
	"fgrep":    func([]word) bool { return true },
	"rg":       func(a []word) bool { return !hasArgPrefix(a, "--pre") },
	"sed":      sedReadOnly,
	"awk":      awkReadOnly,
	"gawk":     awkReadOnly,
	"mawk":     awkReadOnly,
	"env":      func(a []word) bool { return len(a) == 0 },
	"printenv": func(a []word) bool { return len(a) == 0 },
	"php":      func(a []word) bool { return len(a) == 1 && (a[0].s == "-v" || a[0].s == "--version" || a[0].s == "-m") },
	"node":     func(a []word) bool { return len(a) == 1 && (a[0].s == "-v" || a[0].s == "--version") },
	"composer": func(a []word) bool {
		return len(a) >= 1 && (a[0].s == "--version" || a[0].s == "validate" || a[0].s == "show" || a[0].s == "outdated")
	},
	"git": gitReadOnly,
}

// readOnlyCommand reports whether argv (innermost form) is a known read-only
// invocation.
func readOnlyCommand(argv []word) bool {
	name, args := argv[0].s, argv[1:]
	if plainReadOnly[name] {
		return true
	}
	rule, ok := readOnlyRules[name]
	return ok && rule(args)
}

// shortClusterHas: any short option cluster (-abc) containing letter c.
func shortClusterHas(args []word, c byte) bool {
	for _, a := range args {
		if isShortCluster(a.s) && strings.IndexByte(a.s, c) > 0 {
			return true
		}
	}
	return false
}

// sedScripts extracts the script texts of a sed invocation and reports whether
// the options are acceptable (quiet, no in-place edit, no script file).
func sedScripts(args []word) (scripts []string, ok bool) {
	quiet, haveE := false, false
	for i := 0; i < len(args); i++ {
		a := args[i].s
		switch {
		case a == "--quiet" || a == "--silent":
			quiet = true
		case a == "--in-place" || strings.HasPrefix(a, "--in-place=") || a == "-f" || strings.HasPrefix(a, "--file") || a == "-s" || a == "--sandbox":
			return nil, false
		case a == "-e" && i+1 < len(args):
			haveE = true
			scripts = append(scripts, args[i+1].s)
			i++
		case strings.HasPrefix(a, "--expression="):
			haveE = true
			scripts = append(scripts, strings.TrimPrefix(a, "--expression="))
		case isShortCluster(a):
			if strings.ContainsAny(a, "iIfs") {
				return nil, false
			}
			quiet = quiet || strings.Contains(a, "n")
		case strings.HasPrefix(a, "-"):
			// other long options (--regexp-extended, --debug …) are harmless
		case !haveE && len(scripts) == 0:
			scripts = append(scripts, a)
		}
	}
	return scripts, quiet && len(scripts) > 0
}

func sedReadOnly(args []word) bool {
	scripts, ok := sedScripts(args)
	if !ok {
		return false
	}
	for _, s := range scripts {
		if sedBadRe.MatchString(s) {
			return false
		}
	}
	return true
}

func awkReadOnly(args []word) bool {
	prog := ""
	for i := 0; i < len(args); i++ {
		a := args[i].s
		switch {
		case a == "-f" || strings.HasPrefix(a, "--file"):
			return false
		case a == "-F" || a == "-v":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			prog = a
			i = len(args)
		}
	}
	if prog == "" {
		return false
	}
	for _, bad := range []string{"system", "getline", ">", "|", "ENVIRON", "close", "fflush"} {
		if strings.Contains(prog, bad) {
			return false
		}
	}
	return true
}

// gitReadOnly: subcommands that only print.
func gitReadOnly(args []word) bool {
	if len(args) == 0 {
		return false
	}
	sub, rest := args[0].s, args[1:]
	if hasArg(rest, "-o", "-O") || hasArgPrefix(rest, "--output", "--open-files-in-pager") {
		return false
	}
	switch {
	case gitReadSubs[sub]:
		return true
	case sub == "branch":
		return len(positionals(rest)) == 0 && onlyIn(rest, gitBranchOK)
	case sub == "remote":
		return len(rest) == 0 || (len(rest) == 1 && (rest[0].s == "-v" || rest[0].s == "--verbose"))
	case sub == "stash":
		return len(rest) >= 1 && rest[0].s == "list"
	case sub == "config":
		return hasArg(rest, keysOf(gitConfigRd)...)
	}
	return false
}

func onlyIn(args []word, set map[string]bool) bool {
	for _, a := range args {
		if !set[a.s] {
			return false
		}
	}
	return true
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// workspaceOp: commands that change files inside the checkout. Unlisted they
// are allowed at L0/L1; the path rules decide whether each target is fine
// (outside the repo asks, protected paths deny).
func workspaceOp(argv []word) bool {
	switch argv[0].s {
	case "mkdir", "touch", "cp", "mv", "rm":
		return true
	case "git":
		a := argv[1:]
		return len(a) > 0 && a[0].s == "add" && !hasArg(a, "-f", "--force")
	}
	return false
}

// dangerousGitKey: configuration keys that make git run a program, load other
// configuration or rewrite where it talks to.
func dangerousGitKey(key string) bool {
	k := strings.ToLower(key)
	if i := strings.IndexByte(k, '='); i >= 0 {
		k = k[:i]
	}
	for _, p := range []string{"core.", "include.", "includeif.", "filter.", "alias.", "credential.", "pager.", "protocol.", "url.", "gpg.", "sequence."} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	if k == "diff.external" || (strings.HasPrefix(k, "diff.") && (strings.HasSuffix(k, ".textconv") || strings.HasSuffix(k, ".command"))) {
		return true
	}
	for _, s := range []string{".command", ".cmd", ".program", ".helper", ".textconv", ".sshcommand", ".fsmonitor", ".hookspath", ".editor", ".pager", ".askpass", ".external", ".insteadof", ".pushinsteadof"} {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// gitConfigWrite reports whether `git config ...` sets or edits a dangerous key.
func gitConfigWrite(argv []word) bool {
	if len(argv) < 2 || argv[1].s != "config" || hasArg(argv[2:], keysOf(gitConfigRd)...) {
		return false
	}
	if hasArg(argv[2:], "-e", "--edit") {
		return true
	}
	for _, a := range argv[2:] {
		if !strings.HasPrefix(a.s, "-") && dangerousGitKey(a.s) {
			return true
		}
	}
	return false
}
