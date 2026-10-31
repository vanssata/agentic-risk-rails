package guard

import (
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// inert shell builtins and trivial utilities: allowed unless a list says otherwise
// (their redirections and arguments are still path-checked).
var inert = opts("cd", "pwd", "true", "false", ":", "test", "[", "echo", "printf", "exit", "return", "wait", "sleep")

// path roles of well-known commands (arguments that name files).
var (
	readers = opts("cat", "less", "more", "head", "tail", "bat", "nl", "od", "xxd", "strings", "grep", "egrep", "fgrep", "rg", "wc", "diff", "sort", "tac", "cut", "file", "stat", "base64", "sha256sum", "md5sum", "awk", "sed", "cp", "ls", "find", "tr", "uniq", "jq", "yq", "tar", "zip", "unzip")
	writers = opts("tee", "mv", "rm", "touch", "mkdir", "rmdir", "chmod", "chown", "ln", "truncate", "install", "shred", "unlink", "dd")
)

func checkBash(call core.ToolCall, gc core.GuardContext) core.Verdict {
	var r result
	e := gc.Policy.Policy.Enforcement
	if strings.TrimSpace(call.Command) == "" {
		return deny("empty shell command")
	}
	a := analyze(call.Command, 0)
	for _, why := range a.unrecog {
		r.add(core.Verdict{Decision: askOrDeny(gc), Reason: "unrecognised shell construct: " + why, Rule: "enforcement.commands.parser"})
	}
	for _, c := range a.cmds {
		r.add(checkCommand(c, e, gc))
		if !c.passthrough {
			checkArgs(&r, c.last(), call, e, gc)
		}
	}
	for _, rd := range a.redirs {
		r.add(checkPath(rd.target.s, rd.write, call, gc, true))
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

// checkCommand applies commands.deny > ask > allow, then unlisted.
func checkCommand(c cmd, e core.EnforcementSpec, gc core.GuardContext) core.Verdict {
	for _, f := range c.forms {
		for _, pat := range e.Commands.Deny {
			if matchCommand(pat, f) {
				return core.Verdict{Decision: core.Deny, Reason: "command denied: " + text(f), Rule: "enforcement.commands.deny: " + pat}
			}
		}
	}
	for _, f := range c.forms {
		for _, pat := range e.Commands.Ask {
			if matchCommand(pat, f) {
				return core.Verdict{Decision: core.Ask, Reason: "command needs approval: " + text(f), Rule: "enforcement.commands.ask: " + pat}
			}
		}
	}
	if c.passthrough {
		return core.Verdict{Decision: core.Allow}
	}
	last := c.last()
	for _, pat := range e.Commands.Allow {
		if matchCommand(pat, last) {
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

// checkArgs checks file arguments and network hosts of the innermost command.
func checkArgs(r *result, argv []word, call core.ToolCall, e core.EnforcementSpec, gc core.GuardContext) {
	name := argv[0].s
	hosts, unresolved := hostsOf(argv)
	for _, h := range hosts {
		r.add(checkHost(h, h, e, gc))
	}
	if unresolved {
		r.add(checkHost("", text(argv), e, gc))
	}
	var args []word
	for _, w := range argv[1:] {
		if !strings.HasPrefix(w.s, "-") || w.dyn {
			args = append(args, w)
		}
	}
	var writes, reads []word
	switch {
	case name == "cp" && len(args) > 1:
		writes, reads = args[len(args)-1:], args[:len(args)-1]
	case name == "sed" && hasFlag(argv, "-i", "--in-place"):
		if len(args) > 1 {
			writes = args[1:]
		}
	case name == "dd":
		for _, w := range args {
			if v, ok := strings.CutPrefix(w.s, "of="); ok {
				writes = append(writes, word{s: v})
			} else if v, ok := strings.CutPrefix(w.s, "if="); ok {
				reads = append(reads, word{s: v})
			}
		}
	case writers[name]:
		writes = args
	default:
		reads = args // any command may read what it is pointed at
	}
	for _, w := range writes {
		r.add(pathArg(w, true, call, gc, name))
	}
	for _, w := range reads {
		if w.dyn && !readers[name] {
			continue
		}
		if !w.dyn && strings.ContainsAny(w.s, " \t") {
			continue // prose such as a commit message, not a path
		}
		r.add(pathArg(w, false, call, gc, name))
	}
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

func pathArg(w word, write bool, call core.ToolCall, gc core.GuardContext, name string) core.Verdict {
	if w.dyn {
		return core.Verdict{Decision: askOrDeny(gc), Reason: "file argument of " + name + " not static", Rule: "enforcement.commands.parser"}
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
