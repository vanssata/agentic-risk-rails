package claude

import (
	"context"
	"fmt"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

type agentSpec struct {
	file, name, desc, tools, body string
	tier                          core.Tier
}

var agentSpecs = []agentSpec{
	{
		file: "rr-scout", name: "rr-scout", tier: core.TierFast, tools: "Read, Glob, Grep",
		desc: "Read-only research scout. Use to map code, tests or docs and report findings with file:line sources.",
		body: "You are a read-only scout. Answer the brief with facts and sources (file:line or URL). Do not edit files. Report status DONE, DONE_WITH_CONCERNS, BLOCKED or NEEDS_CONTEXT first.",
	},
	{
		file: "rr-implementer", name: "rr-implementer", tier: core.TierBalanced,
		desc: "Implements one plan step inside its declared file scope, test first. Use for a single, well-specified step.",
		body: "You implement exactly one step. Touch only the files named in the step. Write the test first, then the code, then run the step's checks. Report status DONE, DONE_WITH_CONCERNS, BLOCKED or NEEDS_CONTEXT first.",
	},
	{
		file: "rr-reviewer", name: "rr-reviewer", tier: core.TierStrong, tools: "Read, Glob, Grep, Bash",
		desc: "Reviews a diff against its spec and the project policy. Use after an implementer reports DONE.",
		body: "You review a diff against its step spec and riskrails.yaml. You do not edit files. List blocking findings first, each with file:line and a reason, then non-blocking notes. Verdict: APPROVE or CHANGES_REQUESTED.",
	},
}

type agentsGen struct{}

func (agentsGen) Name() string { return "claude-agents" }

func (agentsGen) Render(_ context.Context, in core.SyncInput) ([]core.File, error) {
	t := in.Tiers[Name]
	var files []core.File
	for _, a := range agentSpecs {
		var b strings.Builder
		b.WriteString("---\n")
		fmt.Fprintf(&b, "name: %s\ndescription: %s\n", a.name, a.desc)
		if a.tools != "" {
			fmt.Fprintf(&b, "tools: %s\n", a.tools)
		}
		if m := resolveModel(t, a.tier); m != "" {
			fmt.Fprintf(&b, "model: %s\n", m)
		}
		if eff := in.Policy.Policy.Models.Effort[a.tier]; eff != "" {
			fmt.Fprintf(&b, "effort: %s\n", eff)
		}
		b.WriteString("---\n\n" + a.body + "\n")
		files = append(files, core.File{Path: ".claude/agents/" + a.file + ".md", Content: []byte(b.String())})
	}
	return files, nil
}

// resolveModel returns the PASS model for tier, following the ladder when the
// tier has none. "" means omit the line so the subagent inherits the session
// (DES §4.5b): a model that is not in Models never appears.
func resolveModel(t core.EffectiveTiers, tier core.Tier) string {
	for i := 0; i <= len(core.Tiers) && tier != ""; i++ {
		if m := t.Models[tier]; m != "" {
			return m
		}
		tier = t.Ladder[tier]
	}
	return ""
}
