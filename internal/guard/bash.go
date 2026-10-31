package guard

import (
	"os"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// inert shell builtins and trivial utilities: allowed unless a list says otherwise
// (their redirections and arguments are still path-checked).
var inert = opts("cd", "pushd", "popd", "pwd", "true", "false", ":", "test", "[", "echo", "printf", "exit", "return", "wait", "sleep")

// harmless with dynamic arguments: they only print or wait.
var dynOK = opts("echo", "printf", "true", "false", ":", "sleep", "wait", "exit", "return")

// path roles of well-known commands (arguments that name files).
var (
	readers = opts("cat", "less", "more", "head", "tail", "bat", "nl", "od", "xxd", "strings", "grep", "egrep", "fgrep", "rg", "wc", "diff", "sort", "tac", "cut", "file", "stat", "base64", "sha256sum", "md5sum", "awk", "sed", "cp", "ls", "find", "tr", "uniq", "jq", "yq", "tar", "zip", "unzip")
	writers = opts("tee", "mv", "rm", "touch", "mkdir", "rmdir", "chmod", "chown", "ln", "truncate", "install", "shred", "unlink", "dd")
	// commands whose -o takes an output file
	shortOutput = opts("curl", "wget", "sort", "gcc", "cc", "clang", "g++")
)

func unrecognised(why string, gc core.GuardContext) core.Verdict {
	return core.Verdict{Decision: askOrDeny(gc), Reason: "unrecognised shell construct: " + why, Rule: "enforcement.commands.parser"}
}

func checkBash(call core.ToolCall, gc core.GuardContext) core.Verdict {
	var r result
	e := gc.Policy.Policy.Enforcement
	if strings.TrimSpace(call.Command) == "" {
		return deny("empty shell command")
	}
	a := analyze(call.Command, call.Cwd, 0)
	for _, why := range a.unrecog {
		r.add(unrecognised(why, gc))
	}
	for _, why := range a.denies {
		r.add(core.Verdict{Decision: core.Deny, Reason: why, Rule: "guard.git_config"})
	}
	for _, c := range a.cmds {
		v := checkCommand(c, e, gc)
		r.add(v)
		if !c.passthrough && v.Decision != core.Deny { // a denied command cannot get stricter
			checkArgs(&r, c, call, e, gc)
		}
	}
	for _, rd := range a.redirs {
		rc := call
		rc.Cwd = rd.cwd
		r.add(checkPath(rd.target.s, rd.write, rc, gc, true))
	}
	return r.done()
}

func text(argv []word) string {
	s := make([]string, len(argv))
	for i, w := range argv {
		s[i] = w.s
	}
	return strings.Join(s, " ")
}

// checkCommand applies commands.deny > ask > allow, then unlisted. Deny and ask
// patterns are loose globs (over-matching is safe); allow patterns are strict:
// `cmd*` never extends the word `cmd` itself.
func checkCommand(c cmd, e core.EnforcementSpec, gc core.GuardContext) core.Verdict {
	for _, f := range c.forms {
		for _, pat := range e.Commands.Deny {
			if matchCommand(pat, f, false) {
				return core.Verdict{Decision: core.Deny, Reason: "command denied: " + text(f), Rule: "enforcement.commands.deny: " + pat}
			}
		}
	}
	for _, f := range c.forms {
		for _, pat := range e.Commands.Ask {
			if matchCommand(pat, f, false) {
				return core.Verdict{Decision: core.Ask, Reason: "command needs approval: " + text(f), Rule: "enforcement.commands.ask: " + pat}
			}
		}
	}
	if c.passthrough {
		return core.Verdict{Decision: core.Allow}
	}
	last := c.last()
	for _, pat := range e.Commands.Allow {
		if matchCommand(pat, last, true) {
			return core.Verdict{Decision: core.Allow, Reason: "command allowed: " + text(last), Rule: "enforcement.commands.allow: " + pat}
		}
	}
	if inert[last[0].s] {
		return core.Verdict{Decision: core.Allow, Reason: "inert builtin", Rule: "guard.inert"}
	}
	if gc.Level < core.L2 && !privileged(c) && (readOnlyCommand(last) || workspaceOp(last)) {
		// L0/L1 only. Arguments are still path-checked, so secrets stay denied.
		return core.Verdict{Decision: core.Allow, Reason: "known read-only or workspace command: " + text(last), Rule: "guard.readonly"}
	}
	d := core.Ask
	if e.Commands.Unlisted != nil {
		d = *e.Commands.Unlisted
	}
	if gc.Level >= core.L2 {
		d = core.Deny
	}
	return core.Verdict{Decision: d, Reason: "command not in any list: " + text(last), Rule: "enforcement.commands.unlisted"}
}

// noFileSemantics: commands whose arguments are not files to read or write.
var noFileSemantics = opts("echo", "printf", "true", "false", ":", "sleep", "wait", "exit", "return", "cd", "pushd", "popd", "test", "[", "pwd")

type pathKind int

const (
	pathRead pathKind = iota
	pathWrite
	pathEither // flag values: read rules plus deny-type write rules
)

// checkArgs checks file arguments, network hosts and pushes of the innermost
// command. Every argument and flag value is a potential path; an argument that
// is an existing directory is a recursive read target.
func checkArgs(r *result, c cmd, call core.ToolCall, e core.EnforcementSpec, gc core.GuardContext) {
	argv := c.last()
	name := argv[0].s
	call.Cwd = c.cwd
	hosts, unresolved := hostsOf(argv)
	for _, h := range hosts {
		r.add(checkHost(h, h, e, gc))
	}
	if unresolved {
		r.add(checkHost("", text(argv), e, gc))
	}
	if !dynOK[name] {
		for _, w := range argv[1:] {
			if w.dyn {
				r.add(unrecognised("dynamic argument to "+name, gc))
				break
			}
		}
	}
	if c.xargs && (writers[name] || readers[name]) {
		r.add(unrecognised("xargs "+name+" with a list from stdin", gc))
	}
	if name == "git" {
		r.add(checkPush(argv, gc))
		if gitConfigWrite(argv) {
			r.add(core.Verdict{Decision: core.Deny, Reason: "git config key can run programs, load configuration or rewrite remotes", Rule: "guard.git_config"})
		}
	}
	outW, flagVals, pos := splitArgs(argv, call, gc)
	writes, reads := fileRoles(name, argv, pos)
	writes = append(writes, outW...)
	dirs := dirModeOf(argv)
	if dirs != dirNone && searchesCwd(argv, pos) {
		r.add(checkDir(".", call, gc, dirs)) // `grep -r foo` / `rg foo` search the working directory
	}
	if name == "rm" {
		r.add(checkRmRoot(pos, call, gc))
	}
	for _, w := range writes {
		r.add(pathArg(w, pathWrite, dirs, call, gc))
	}
	for _, w := range reads {
		if !w.dyn && strings.ContainsAny(w.s, " \t") {
			continue // prose such as a commit message, not a path
		}
		r.add(pathArg(w, pathRead, dirs, call, gc))
	}
	for _, w := range flagVals {
		r.add(pathArg(w, pathEither, dirs, call, gc))
	}
}

// pathLike: a token that plausibly names a file (contains "/", starts with "."
// or "~", or exists relative to the working directory).
func pathLike(s string, call core.ToolCall, gc core.GuardContext) bool {
	if s == "" || len(s) > 1024 || strings.ContainsAny(s, "\n") || schemeRe.MatchString(s) {
		return false
	}
	if strings.Contains(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") {
		return true
	}
	_, err := os.Lstat(resolve(s, call.Cwd, gc).abs)
	return err == nil
}

// splitArgs separates positional arguments from flag values. A flag value is
// the part after "=" of any option, or the next token after a "--long" option
// when that token is path-like. (The token also stays positional.) outW holds
// the value of `-o` for commands where it names an output file.
func splitArgs(argv []word, call core.ToolCall, gc core.GuardContext) (outW, flagVals, pos []word) {
	for i := 1; i < len(argv); i++ {
		w := argv[i]
		if !strings.HasPrefix(w.s, "-") || w.s == "-" {
			pos = append(pos, w)
			continue
		}
		val := func(s string) word { return word{s: s, dyn: w.dyn, glob: w.glob} }
		_, v, eq := strings.Cut(w.s, "=")
		short := !strings.HasPrefix(w.s, "--")
		switch {
		case eq && v != "":
			flagVals = append(flagVals, val(v))
		case short && len(w.s) > 2 && w.s[1] == 'o' && shortOutput[argv[0].s]:
			outW = append(outW, val(w.s[2:]))
		case w.s == "-o" && shortOutput[argv[0].s] && i+1 < len(argv):
			outW = append(outW, argv[i+1])
			i++
		case !short && !eq && i+1 < len(argv) && !strings.HasPrefix(argv[i+1].s, "-") && !argv[i+1].dyn && pathLike(argv[i+1].s, call, gc):
			flagVals = append(flagVals, argv[i+1])
		}
	}
	return
}

// checkPush denies pushes that target the default branch or force with "+".
func checkPush(argv []word, gc core.GuardContext) core.Verdict {
	if len(argv) < 2 || argv[1].s != "push" {
		return core.Verdict{}
	}
	def := gc.Policy.Policy.Project.DefaultBranch
	if def == "" {
		def = "main"
	}
	for _, w := range argv[2:] {
		if strings.HasPrefix(w.s, "-") {
			continue
		}
		ref := w.s
		if strings.HasPrefix(ref, "+") {
			return core.Verdict{Decision: core.Deny, Reason: "force-push refspec " + w.s, Rule: "guard.push_force_refspec"}
		}
		if i := strings.LastIndexByte(ref, ':'); i >= 0 {
			ref = ref[i+1:]
		}
		ref = strings.TrimPrefix(ref, "refs/heads/")
		if strings.EqualFold(ref, def) {
			return core.Verdict{Decision: core.Deny, Reason: "push to default branch " + def, Rule: "guard.push_default_branch"}
		}
	}
	return core.Verdict{}
}

func hasFlag(argv []word, names ...string) bool {
	for _, w := range argv[1:] {
		for _, n := range names {
			if w.s == n || (n == "-i" && strings.HasPrefix(w.s, "-i")) {
				return true
			}
		}
	}
	return false
}

func pathArg(w word, kind pathKind, dirs dirMode, call core.ToolCall, gc core.GuardContext) core.Verdict {
	if w.dyn {
		return core.Verdict{} // already reported as unrecognised
	}
	paths := []string{w.s}
	if w.glob {
		paths = globTargets(w.s, call.Cwd, gc)
	}
	var r result
	for _, p := range paths {
		switch kind {
		case pathRead:
			r.add(checkPath(p, false, call, gc, true))
		case pathWrite:
			r.add(checkPath(p, true, call, gc, true))
		default:
			r.add(checkEither(p, call, gc, true))
		}
		if dirs != dirNone {
			r.add(checkDir(p, call, gc, dirs))
		}
	}
	return r.done()
}

// fileRoles says which positional arguments of a command are written and which are read.
func fileRoles(name string, argv, args []word) (writes, reads []word) {
	switch {
	case name == "cp" && len(args) > 1:
		return args[len(args)-1:], args[:len(args)-1]
	case name == "sed" && hasFlag(argv, "-i", "--in-place"):
		if len(args) > 1 {
			return args[1:], nil
		}
		return nil, nil
	case name == "dd":
		for _, w := range args {
			if v, ok := strings.CutPrefix(w.s, "of="); ok {
				writes = append(writes, word{s: v})
			} else if v, ok := strings.CutPrefix(w.s, "if="); ok {
				reads = append(reads, word{s: v})
			}
		}
		return writes, reads
	case writers[name]:
		return args, nil
	}
	return nil, args // any command may read what it is pointed at
}

// dirMode says how an existing directory used as an argument is judged.
type dirMode int

const (
	dirNone    dirMode = iota // names only (ls, find, git add …): no content is read
	dirContent                // reads content: secrets below the directory deny
	dirTracked                // reads content but honours .gitignore (rg, git grep)
)

var nameOnly = opts("ls", "tree", "du", "df", "stat", "find", "mkdir", "touch", "rm", "mv", "chmod", "chown", "ln",
	"which", "type", "basename", "dirname", "realpath", "readlink", "file", "composer", "npm", "yarn", "pnpm")

func dirModeOf(argv []word) dirMode {
	name, args := argv[0].s, argv[1:]
	switch {
	case noFileSemantics[name] || nameOnly[name]:
		return dirNone
	case name == "git":
		switch {
		case len(args) == 0:
			return dirNone
		case args[0].s == "grep":
			// --no-index searches ignored files too unless --exclude-standard
			if hasArg(args, "--no-exclude-standard") || (hasArg(args, "--no-index") && !hasArg(args, "--exclude-standard")) {
				return dirContent
			}
			return dirTracked
		case args[0].s == "diff" && hasArg(args, "--no-index"):
			return dirContent
		}
		return dirNone
	case name == "rg":
		if hasArgPrefix(args, "--no-ignore", "-u", "--unrestricted") {
			return dirContent
		}
		return dirTracked
	}
	return dirContent
}

// checkRmRoot asks before removing the repository root itself.
func checkRmRoot(pos []word, call core.ToolCall, gc core.GuardContext) core.Verdict {
	for _, w := range pos {
		if w.dyn || w.glob {
			continue
		}
		if t := resolve(w.s, call.Cwd, gc); t.inside && t.rel == "." {
			return core.Verdict{Decision: askOrDeny(gc), Reason: "rm of the repository root", Rule: "guard.rm_root"}
		}
	}
	return core.Verdict{}
}

// privileged: some wrapper level elevates (sudo/doas/su), so the innermost
// command is not what it seems and gets no default allow.
func privileged(c cmd) bool {
	for _, f := range c.forms[:len(c.forms)-1] {
		switch f[0].s {
		case "sudo", "doas", "su":
			return true
		}
	}
	return false
}

// searchesCwd: a recursive search command without a path operand searches ".".
func searchesCwd(argv, pos []word) bool {
	name, args := argv[0].s, argv[1:]
	recursive := false
	switch name {
	case "rg":
		recursive = true
	case "grep", "egrep", "fgrep":
		recursive = hasArg(args, "--recursive", "--dereference-recursive") || shortClusterHas(args, 'r') || shortClusterHas(args, 'R')
	case "git":
		recursive = len(args) > 0 && args[0].s == "grep"
		pos = pos[min(1, len(pos)):] // drop the subcommand
	}
	if !recursive {
		return false
	}
	valued := 0 // -e PATTERN / -f FILE consume a positional-looking word
	for _, a := range args {
		if a.s == "-e" || a.s == "-f" || a.s == "--regexp" || a.s == "--file" {
			valued++
		}
	}
	if valued > 0 || hasArgPrefix(args, "--regexp=", "--file=") {
		return len(pos) <= valued
	}
	return len(pos) <= 1
}
