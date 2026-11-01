// Package opencode is the degrade-mode adapter for OpenCode. It generates
// opencode.json permissions (a native layer, ask/allow/deny) but no enforcing
// hook is confirmed (docs/research/verified/degrade.md), so Enforcement is
// ci_only: autonomy ≤ L1, protection is CI.
package opencode

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/adapters/degrade"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

// Name is the runtime name.
const Name = "opencode"

func init() { runtimes.Register(Adapter{degrade.NoHooks{ID: Name}}) }

// Adapter implements core.RuntimeAdapter without hooks.
type Adapter struct{ degrade.NoHooks }

func (Adapter) Generators() []core.Generator { return []core.Generator{permGen{}} }

type permGen struct{}

func (permGen) Name() string { return "opencode" }

// pair is one JSON member; OpenCode applies the LAST matching rule, so order matters.
type pair struct{ k, v string }

type ordered []pair

func (o ordered) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(p.k)
		v, _ := json.Marshal(p.v)
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// Render compiles the policy to opencode.json. The file is wholly generated.
func (permGen) Render(_ context.Context, in core.SyncInput) ([]core.File, error) {
	e := in.Policy.Policy.Enforcement
	unlisted := "ask"
	if e.Commands.Unlisted != nil {
		unlisted = string(*e.Commands.Unlisted)
	}
	bash := ordered{{"*", unlisted}}
	for _, c := range e.Commands.Allow {
		bash = append(bash, pair{c, "allow"})
	}
	for _, c := range e.Commands.Ask {
		bash = append(bash, pair{c, "ask"})
	}
	for _, c := range e.Commands.Deny {
		bash = append(bash, pair{c, "deny"})
	}
	edit := ordered{{"*", "allow"}}
	for _, p := range degrade.Protected(e) {
		edit = append(edit, pair{p, "deny"})
	}
	read := ordered{{"*", "allow"}}
	for _, p := range e.SecretReads {
		read = append(read, pair{p, "deny"})
	}
	cfg := map[string]any{"permission": map[string]any{"bash": bash, "edit": edit, "read": read}}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return []core.File{{Path: "opencode.json", Content: append(b, '\n')}}, nil
}
