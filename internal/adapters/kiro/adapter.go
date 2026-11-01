// Package kiro is the degrade-mode adapter for Kiro. Kiro has PreToolUse hooks
// (.kiro/hooks/*.json) but how a command hook blocks a call is unconfirmed
// (docs/research/verified/degrade.md), so nothing is generated for it and
// Enforcement is ci_only: autonomy ≤ L1, protection is CI.
package kiro

import (
	"github.com/vanssata/agentic-risk-rails/internal/adapters/degrade"
	"github.com/vanssata/agentic-risk-rails/internal/runtimes"
)

// Name is the runtime name.
const Name = "kiro"

func init() { runtimes.Register(New()) }

// Adapter implements core.RuntimeAdapter without hooks.
type Adapter struct{ degrade.NoHooks }

// New returns the adapter.
func New() Adapter { return Adapter{degrade.NoHooks{ID: Name}} }
