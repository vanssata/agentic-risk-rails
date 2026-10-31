// Package guard implements core.Guard: the PreToolUse tripwire (ADR-9).
//
// It is a tripwire, not a boundary (DES §3.4 step 0, §14.7): allowed commands
// run code the agent wrote, and egress or path analysis of shell strings is
// best effort. The OS sandbox compiled by `rr sync` is the boundary; this
// package makes the common bypass classes loud and fails closed on the rest.
//
// The rules, in the order they are applied (strictest verdict wins; at L>=2
// every ask becomes deny; any panic, error or timeout is deny):
//
//  1. riskrails.yaml via Edit/Write: the policy diff decides, before
//     protected_paths. Loader/Differ nil, parse/diff error, empty content,
//     several paths in one call, or LOOSEN/MIXED => deny; TIGHTEN => allow.
//  2. Shell text is parsed with mvdan/sh. Every simple command at any depth
//     (substitutions, subshells, loops, `bash -c` strings, heredoc bodies,
//     `find -exec`) is checked. Wrappers (env, sudo, xargs, timeout, ...) are
//     unwrapped; `git -C dir` is a cd for that command; every other git global
//     option except --no-pager/--no-optional-locks is unrecognised, and
//     `git -c`/`git config` with a key that runs programs, loads configuration
//     or rewrites remotes (core.*, include*, filter.*, alias.*, credential.*,
//     url.*, diff.external/textconv, gpg.program, sequence.editor ...) is deny.
//  3. UNRECOGNISED => ask (deny at L>=2): eval/source/alias/trap, a command name
//     or argument that is not a literal, a non-static cd, shell reading stdin,
//     function definitions, risky globals, and any env assignment before a
//     command except a static APP_ENV/APP_DEBUG/NODE_ENV/CI/TZ/LANG/LC_*.
//  4. Commands: deny > ask > allow > default allow > unlisted. Deny/ask patterns
//     match every wrapper level and tolerate option tokens between words; allow
//     patterns are strict (`cmd*` never extends `cmd` itself) and match only the
//     innermost command. DEFAULT ALLOW (L0/L1 only, never under sudo/doas): known
//     read-only commands (ls, cat, grep, find without -exec, sed -n, git status/
//     log/diff ... see readonly.go) and workspace commands (mkdir, touch, cp, mv,
//     rm, git add) whose path arguments pass rule 5. Other unlisted commands use
//     commands.unlisted (deny at L>=2).
//  5. Every argument is a path: reads are checked against secret_reads/no_read;
//     writes against core.AlwaysProtected, protected_paths, sandbox.*, the scope
//     guard and the repo root. Flag values (`--x=v`, or the path-like token after
//     `--x`) get the read rules AND the deny-type write rules. An existing
//     directory argument of a command that READS CONTENT (cat, tar, cp, rsync,
//     grep -r, git diff --no-index, unknown commands; and the implicit "." of
//     `grep -r foo`) is a recursive read: denied if a secret lies below it. Name-
//     only commands (ls, find, du, git add/status ...) are exempt; rg, git grep
//     and Grep/Glob skip files git ignores (absent from RepoFiles).
//  6. Hosts of known network commands and URL tools must be in egress.allow
//     when deny_default is set (a tripwire, not a boundary).
//  7. Grep/Glob: the search root must not contain secret files git would show
//     unless ONE plain positive glob excludes them all.
//  8. Unknown (MCP) tools: every string in the raw input is classified as path,
//     URL, shell text (keys command/cmd/script/code/shell/sh) or model, and the
//     matching rules apply.
//  9. Agent/Task with an explicit model must match an effective tier (alias aware);
//     with no tiers wired it asks.
package guard

import (
	"context"
	"fmt"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

type guard struct{}

// New returns the production guard.
func New() core.Guard { return guard{} }

func deny(reason string) core.Verdict {
	return core.Verdict{Decision: core.Deny, Reason: reason, Rule: "guard.fail_closed"}
}

// Check is fail-closed: panics, an expired context and invalid decisions all deny.
func (guard) Check(ctx context.Context, call core.ToolCall, gc core.GuardContext) core.Verdict {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return deny("guard: " + err.Error())
	}
	ch := make(chan core.Verdict, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- deny(fmt.Sprintf("guard: internal error: %v", r))
			}
		}()
		ch <- evaluate(call, gc)
	}()
	var v core.Verdict
	select {
	case v = <-ch:
	case <-ctx.Done():
		return deny("guard: " + ctx.Err().Error())
	}
	switch v.Decision {
	case core.Allow, core.Ask, core.Deny:
	default:
		return deny("guard: invalid decision")
	}
	if v.Decision == core.Ask && gc.Level >= core.L2 {
		v.Decision = core.Deny
		v.Reason += " (ask is deny at L2+)"
	}
	return v
}

// result folds verdicts to the strictest; the first of equal strictness wins.
type result struct{ v core.Verdict }

func (r *result) add(v core.Verdict) {
	if v.Decision == "" || (v.Decision == core.Allow && v.Reason == "" && v.Rule == "") {
		return // silent allow: nothing to report
	}
	if r.v.Decision == "" || v.Decision.Rank() > r.v.Decision.Rank() {
		r.v = v
	}
}

func (r *result) done() core.Verdict {
	if r.v.Decision == "" {
		return core.Verdict{Decision: core.Allow, Reason: "no guard rule matched"}
	}
	return r.v
}

// askOrDeny is the decision for "not allowed by default" findings.
func askOrDeny(gc core.GuardContext) core.Decision {
	if gc.Level >= core.L2 {
		return core.Deny
	}
	return core.Ask
}

func evaluate(call core.ToolCall, gc core.GuardContext) core.Verdict {
	if call.Tool == "" && call.Command == "" {
		return deny("malformed tool call: no tool")
	}
	var r result
	tool := strings.ToLower(call.Tool)
	enf := gc.Policy.Policy.Enforcement

	switch tool {
	case "agent", "task":
		r.add(checkModel(call, gc))
	case "edit", "multiedit", "write", "notebookedit":
		if v, handled := checkPolicyFile(call, gc); handled {
			return v
		}
		for _, p := range call.Paths {
			r.add(checkPath(p, true, call, gc, false))
		}
	case "read":
		for _, p := range call.Paths {
			r.add(checkPath(p, false, call, gc, false))
		}
	case "glob", "grep":
		r.add(checkSearch(call, gc))
	case "webfetch", "websearch":
		if call.URL != "" {
			r.add(checkHost(hostOfURL(call.URL), call.URL, enf, gc))
		}
	default:
		r.add(checkUnknownTool(call, gc))
	}
	return r.done()
}
