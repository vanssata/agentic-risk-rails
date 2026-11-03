package factory

import (
	"context"
	"errors"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// CodexRunner runs a worker as `codex exec` with cwd = the step worktree.
// Models maps a tier to the model passed to --model (from EffectiveTiers).
// Wave 5 contract stub: W5-A implements Run; until then it fails closed.
type CodexRunner struct {
	Bin      string // default "codex"
	Models   map[core.Tier]string
	readOnly bool          // set by ReadOnly(): reviewers and scouts cannot write
	Timeout  time.Duration // per worker; 0 = DefaultTimeout, never unlimited
}

// ReadOnly returns a copy that can only read.
func (c CodexRunner) ReadOnly() core.WorkerRunner {
	c.readOnly = true
	return c
}

func (c CodexRunner) Run(context.Context, core.WorkerSpec) (core.WorkerReport, error) {
	return core.WorkerReport{}, errors.New("codex runner: not implemented")
}
