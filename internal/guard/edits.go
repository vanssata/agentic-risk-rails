package guard

import (
	"path/filepath"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// checkEdits judges a multi-file edit: every edit is evaluated as its own
// single-file Edit (riskrails.yaml by policy diff, everything else by the
// write rules) and the strictest verdict wins; the first denied path is named.
func checkEdits(call core.ToolCall, gc core.GuardContext) core.Verdict {
	want := map[string]bool{}
	for _, e := range call.Edits {
		want[filepath.Clean(e.Path)] = true
		if e.From != "" {
			want[filepath.Clean(e.From)] = true
		}
	}
	got := map[string]bool{}
	for _, p := range call.Paths {
		got[filepath.Clean(p)] = true
	}
	if len(want) != len(got) {
		return deny("inconsistent multi-file edit: Paths do not match Edits")
	}
	for p := range want {
		if !got[p] {
			return deny("inconsistent multi-file edit: Paths do not match Edits")
		}
	}
	var r result
	for _, e := range call.Edits {
		r.add(checkOneEdit(call, e, gc))
	}
	return r.done()
}

// checkOneEdit: a delete or a move never touches riskrails.yaml (no diff can
// bless it); a plain write of it goes through the policy diff.
func checkOneEdit(call core.ToolCall, e core.FileEdit, gc core.GuardContext) core.Verdict {
	one := call
	one.Edits, one.Raw = nil, nil
	removes := e.Delete || e.From != ""
	touched := []string{e.Path}
	if e.From != "" {
		touched = append(touched, e.From)
	}
	var r result
	for _, p := range touched {
		if !isPolicyFile(resolve(p, call.Cwd, gc)) {
			r.add(checkPath(p, true, one, gc, false))
			continue
		}
		if removes {
			r.add(core.Verdict{Decision: core.Deny, Reason: p + ": riskrails.yaml cannot be deleted or moved", Rule: "enforcement.protected_paths: " + policyFile})
			continue
		}
		one.Tool, one.Paths, one.Content = "Edit", []string{p}, e.Content
		v, _ := checkPolicyFile(one, gc)
		v.Reason = p + ": " + v.Reason
		r.add(v)
	}
	return r.done()
}
