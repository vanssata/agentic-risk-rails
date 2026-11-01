package verify

import (
	"context"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// CloseInput is the host's call for the closing full run (W4-A).
type CloseInput struct {
	Root    string
	Task    string
	Spec    core.VerifySpec // from the resolved policy
	Mode    core.Mode       // from TaskMode
	Trust   Trust           // from LoadTrust
	Journal core.Journal
	Actor   core.Actor           // who starts this run: only human, autonomy (runner) or ci make it trusted
	Actors  []core.VerifyAdapter // nil: the built-in adapters
}

// Close runs the closing full run in-process and returns the two facts computed
// from THAT run: GreenNow = the run passed (tree unchanged during it, caches
// aside) and was started by a trusted actor; InScope = the changes seen before
// the run, ignored files included, all match the task scope. It never reads an
// earlier verify_run. The journal event carries trusted=true only for a trusted
// actor. The caller must run it after the agent's processes have stopped.
func Close(ctx context.Context, in CloseInput) (Facts, error) {
	changed, err := TaskChanged(ctx, in.Root, in.Trust, true)
	if err != nil {
		return Facts{}, err
	}
	rep, err := Run(ctx, Input{
		Root: in.Root, Task: in.Task, Changed: changed, Spec: in.Spec, Mode: in.Mode, Closing: true,
		Tree:    func(ctx context.Context) (string, error) { return TreeFingerprint(ctx, in.Root) },
		Journal: in.Journal, Actor: in.Actor, Actors: in.Actors,
	})
	if err != nil {
		return Facts{}, err
	}
	f := Facts{GreenNow: rep.Passed && Trusted(in.Actor)}
	f.InScope, f.OutOfScope = inScope(changed, in.Trust.Scope)
	return f, nil
}
