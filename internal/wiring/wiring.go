// Package wiring holds the injection points that connect modules built in
// parallel. Defaults are strict stand-ins; the orchestrator replaces them with
// real implementations between waves (and W4-A owns the final wiring).
//
// Not yet defined (deferred to W3-A/W4-A): where a hook process learns the
// current task, Level and StepFiles. Until then: no task, L1, scope guard off.
package wiring

import (
	"context"
	"os"
	"path/filepath"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// StrictEffective is the effective policy used before the resolver is wired.
func StrictEffective() core.EffectivePolicy {
	return core.EffectivePolicy{Policy: core.StrictDefaults(), InForce: core.StrictDefaults()}
}

// GuardContext builds the context for `rr guard` in a repo. Default: strict
// policy, L1, no Loader/Differ ⇒ every riskrails.yaml edit is denied.
var GuardContext = func(_ context.Context, root, _ string) (core.GuardContext, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return core.GuardContext{}, err
	}
	home, _ := os.UserHomeDir()
	return core.GuardContext{Policy: StrictEffective(), Level: core.L1, Root: abs, Home: home}, nil
}
