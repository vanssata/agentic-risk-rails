package guard

import (
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
	for _, c := range a.cmds {
		r.add(checkCommand(c, e, gc))
		if !c.passthrough {
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
	d := core.Ask
	if e.Commands.Unlisted != nil {
		d = *e.Commands.Unlisted
	}
	if gc.Level >= core.L2 {
		d = core.Deny
	}
	return core.Verdict{Decision: d, Reason: "command not in any list: " + text(last), Rule: "enforcement.commands.unlisted"}
}

// checkArgs checks file arguments, network hosts and pushes of the innermost
// command. Every argument and flag value is a potential path.
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
	}
	flagW, flagR, pos := splitArgs(argv)
	writes, reads := fileRoles(name, argv, pos)
	writes, reads = append(writes, flagW...), append(reads, flagR...)
	for _, w := range writes {
		r.add(pathArg(w, true, call, gc))
	}
	for _, w := range reads {
		if !w.dyn && strings.ContainsAny(w.s, " \t") {
			continue // prose such as a commit message, not a path
		}
		r.add(pathArg(w, false, call, gc))
	}
}

// writeFlag reports whether a long option names an output file.
func writeFlag(opt string) bool {
	n := strings.ToLower(strings.TrimLeft(opt, "-"))
	for _, no := range []string{"level", "format", "driver", "verbosity", "colo"} {
		if strings.Contains(n, no) {
			return false
		}
	}
	if n == "out" || n == "output" || n == "outfile" || strings.HasPrefix(n, "log") {
		return true
	}
	for _, k := range []string{"output", "coverage", "report", "junit", "dump", "save", "write", "dest"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// splitArgs separates flag values (writes for output-style flags, reads
// otherwise) from positional arguments.
func splitArgs(argv []word) (flagW, flagR, pos []word) {
	for i := 1; i < len(argv); i++ {
		w := argv[i]
		if !strings.HasPrefix(w.s, "-") || w.s == "-" {
			pos = append(pos, w)
			continue
		}
		val := func(s string) word { return word{s: s, dyn: w.dyn, glob: w.glob} }
		switch name, v, eq := strings.Cut(w.s, "="); {
		case eq && v != "":
			if writeFlag(name) {
				flagW = append(flagW, val(v))
			} else {
				flagR = append(flagR, val(v))
			}
		case !strings.HasPrefix(w.s, "--") && len(w.s) > 2 && w.s[1] == 'o' && shortOutput[argv[0].s]:
			flagW = append(flagW, val(w.s[2:]))
		case (writeFlag(w.s) || (w.s == "-o" && shortOutput[argv[0].s])) && !eq && i+1 < len(argv) && !strings.HasPrefix(argv[i+1].s, "-"):
			flagW = append(flagW, argv[i+1])
			i++
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
		if ref == def {
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

func pathArg(w word, write bool, call core.ToolCall, gc core.GuardContext) core.Verdict {
	if w.dyn {
		return core.Verdict{} // already reported as unrecognised
	}
	if w.glob {
		var r result
		for _, p := range globTargets(w.s, call.Cwd, gc) {
			r.add(checkPath(p, write, call, gc, true))
		}
		return r.done()
	}
	return checkPath(w.s, write, call, gc, true)
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
