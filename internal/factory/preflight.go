package factory

import (
	"context"
	"errors"
)

// PreflightIn is what `rr task build` knows before it starts host workers
// (L0/L1; at L>=2 every worker runs in the runner's container instead).
type PreflightIn struct {
	Runtime   string // claude | codex
	Root      string // the checkout; step worktrees live outside it but inherit its trust
	ConfigDir string // $CLAUDE_CONFIG_DIR or $CODEX_HOME as the workers will see it; "" = the runtime's default
	Home      string
}

// Preflight refuses a build whose workers cannot work on this host (errata #65):
// the repo is not trusted by the runtime's config (project permissions ignored),
// the runtime's OS sandbox cannot run a command (functional probe, as errata #42),
// or a tool cache the workers need is not writable inside that sandbox. A failed
// check is a *core.Refusal naming the fix. Wave 6 stub (W6-C): fail closed.
func Preflight(ctx context.Context, in PreflightIn) error {
	return errors.New("factory: Preflight not implemented (wave 6, W6-C)")
}
