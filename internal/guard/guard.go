// Package guard implements core.Guard: the PreToolUse tripwire (ADR-9).
//
// It is a tripwire, not a boundary (DES §3.4 step 0, §14.7): allowed commands
// run code the agent wrote, and egress or path analysis of shell strings is
// best effort. The OS sandbox compiled by `rr sync` is the boundary; this
// package makes the common bypass classes loud and fails closed on the rest.
//
// Evaluation order for one call:
//  1. riskrails.yaml writes by file tools: the policy diff decides (before
//     protected_paths, which normally lists the same file) — LOOSEN denies,
//     TIGHTEN allows ("policy tightened; task becomes full").
//  2. Agent/Task with an explicit model outside the effective tiers: deny.
//  3. Bash: every command (deny > ask > allow, unlisted, unrecognised), then
//     the paths and hosts those commands touch.
//  4. File tools: path rules, scope guard, outside-root writes.
//  5. URL tools: egress.
//
// The strictest verdict wins; at L>=2 every ask becomes deny.
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
	if v.Decision == core.Allow && v.Reason == "" && v.Rule == "" {
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
	case "read", "glob", "grep":
		for _, p := range call.Paths {
			r.add(checkPath(p, false, call, gc, false))
		}
	case "webfetch", "websearch":
		if call.URL != "" {
			r.add(checkHost(hostOfURL(call.URL), call.URL, enf, gc))
		}
	default:
		if call.Command != "" || tool == "bash" {
			r.add(checkBash(call, gc))
		}
		for _, p := range call.Paths { // unknown tool: apply read and write rules
			r.add(checkPath(p, true, call, gc, false))
			r.add(checkPath(p, false, call, gc, false))
		}
		if call.URL != "" {
			r.add(checkHost(hostOfURL(call.URL), call.URL, enf, gc))
		}
	}
	return r.done()
}
