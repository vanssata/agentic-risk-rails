package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Struct field order fixes the key order of the generated JSON.
type settingsDoc struct {
	Permissions permissionsDoc `json:"permissions"`
	Hooks       hooksDoc       `json:"hooks"`
	Sandbox     sandboxDoc     `json:"sandbox"`
}

type permissionsDoc struct {
	Deny  []string `json:"deny"`
	Ask   []string `json:"ask"`
	Allow []string `json:"allow"`
}

type hooksDoc struct {
	PreToolUse []hookGroup `json:"PreToolUse"`
}

type hookGroup struct {
	Matcher string        `json:"matcher"`
	Hooks   []hookCommand `json:"hooks"`
}

type hookCommand struct {
	Type      string `json:"type"`
	Command   string `json:"command"`
	Timeout   int    `json:"timeout"`
	OnFailure string `json:"onFailure"`
}

type sandboxDoc struct {
	Enabled                  bool         `json:"enabled"`
	FailIfUnavailable        bool         `json:"failIfUnavailable"`
	AllowUnsandboxedCommands bool         `json:"allowUnsandboxedCommands"`
	Filesystem               sandboxFSDoc `json:"filesystem"`
}

type sandboxFSDoc struct {
	DenyRead  []string `json:"denyRead"`
	DenyWrite []string `json:"denyWrite"`
}

// hookTimeoutSeconds is short on purpose: a hung guard must not stall the agent,
// and onFailure "block" turns a timeout into a denied call.
const hookTimeoutSeconds = 10

type settingsGen struct{}

func (settingsGen) Name() string { return "claude-settings" }

func (settingsGen) Render(_ context.Context, in core.SyncInput) ([]core.File, error) {
	e := in.Policy.Policy.Enforcement
	sb := e.Sandbox

	var deny, ask []string
	for _, p := range e.ProtectedPaths {
		deny = append(deny, "Edit("+permPath(p)+")")
	}
	for _, p := range expandRefs(append(append([]string{}, e.SecretReads...), sb.NoRead...), e.SecretReads) {
		deny = append(deny, "Read("+permPath(p)+")")
	}
	deny = append(deny, wrap("Bash", e.Commands.Deny)...)
	asks := wrap("Bash", e.Commands.Ask)
	if in.Level >= core.L2 {
		deny = append(deny, asks...) // no human to answer an ask
	} else {
		ask = asks
	}

	fs := sandboxFSDoc{
		DenyRead:  sandboxPaths(in.Home, expandRefs(sb.NoRead, e.SecretReads)),
		DenyWrite: sandboxPaths(in.Home, append(append([]string{}, sb.Readonly...), sb.NoWrite...)),
	}
	required := in.Level >= core.L2
	if sb.RequiredFrom != nil {
		required = in.Level >= *sb.RequiredFrom
	}

	doc := settingsDoc{
		Permissions: permissionsDoc{
			Deny:  dedupe(deny),
			Ask:   dedupe(ask),
			Allow: dedupe(wrap("Bash", e.Commands.Allow)),
		},
		Hooks: hooksDoc{PreToolUse: []hookGroup{{
			Matcher: "*",
			Hooks: []hookCommand{{
				Type: "command", Command: "rr guard --runtime claude --event PreToolUse",
				Timeout: hookTimeoutSeconds, OnFailure: "block",
			}},
		}}},
		Sandbox: sandboxDoc{Enabled: true, FailIfUnavailable: required, Filesystem: fs},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return []core.File{{Path: ".claude/settings.json", Content: buf.Bytes()}}, nil
}

// permPath turns a policy glob into a Read/Edit rule path: "~/x" stays,
// everything else is anchored at the project root ("/x").
func permPath(p string) string {
	switch {
	case strings.HasPrefix(p, "~/"):
		return p
	case strings.HasPrefix(p, "/"):
		return "/" + p // absolute path: "//abs"
	}
	return "/" + strings.TrimPrefix(p, "./")
}

// sandboxPaths expands "~" with home; other paths stay relative to the project root.
func sandboxPaths(home string, paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "~" || strings.HasPrefix(p, "~/") {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
		out = append(out, p)
	}
	return dedupe(out)
}

// expandRefs replaces "$secret_reads" with secrets and drops other "$" refs it cannot resolve.
func expandRefs(list, secrets []string) []string {
	var out []string
	for _, p := range list {
		switch {
		case p == "$secret_reads":
			out = append(out, secrets...)
		case strings.HasPrefix(p, "$"):
			// unknown reference: policy loader rejects these; never emit a literal.
		default:
			out = append(out, p)
		}
	}
	return out
}

func wrap(tool string, patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, tool+"("+p+")")
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
