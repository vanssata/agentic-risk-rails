// Package fakes provides minimal in-memory implementations of the core
// interfaces so modules can be built and tested before their dependencies exist.
package fakes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Journal stores events in memory without hash chaining.
type Journal struct {
	mu     sync.Mutex
	ByTask map[string][]core.Event
	closed map[string]bool
	Err    error // if set, Append fails (to test audit-first callers)
}

func (j *Journal) Append(_ context.Context, e core.Event) (core.Event, error) {
	if j.Err != nil {
		return core.Event{}, j.Err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.ByTask == nil {
		j.ByTask = map[string][]core.Event{}
	}
	j.ByTask[e.Task] = append(j.ByTask[e.Task], e)
	return e, nil
}

func (j *Journal) Events(_ context.Context, task string) ([]core.Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]core.Event(nil), j.ByTask[task]...), nil
}

// Open returns tasks that have events and were not closed.
func (j *Journal) Open(context.Context) ([]string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []string
	for t := range j.ByTask {
		if !j.closed[t] {
			out = append(out, t)
		}
	}
	return out, nil
}

func (j *Journal) Close(_ context.Context, task string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed == nil {
		j.closed = map[string]bool{}
	}
	j.closed[task] = true
	return nil
}

// Types returns the event types recorded for a task, in order.
func (j *Journal) Types(task string) []string {
	evs, _ := j.Events(context.Background(), task)
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Type
	}
	return out
}

// Resolver returns a fixed effective policy.
type Resolver struct {
	Out core.EffectivePolicy
	Err error
}

func (r Resolver) Resolve(context.Context, core.PolicyLayers) (core.EffectivePolicy, error) {
	return r.Out, r.Err
}

// StrictPolicy is the fully defaulted effective policy for goldens and tests.
func StrictPolicy() core.EffectivePolicy {
	return core.EffectivePolicy{Policy: core.StrictDefaults(), InForce: core.StrictDefaults(), PolicySHA: "strict"}
}

// Loader returns a fixed policy or error.
type Loader struct {
	Out core.Policy
	Err error
}

func (l Loader) Parse([]byte) (core.Policy, error) { return l.Out, l.Err }

// Differ returns a fixed direction. The zero value returns "" which Loosens().
type Differ struct {
	Dir     core.Direction
	Changes []core.FieldChange
	Err     error
}

func (d Differ) Diff(core.Policy, core.Policy, []string) (core.Direction, []core.FieldChange, error) {
	return d.Dir, d.Changes, d.Err
}

// Guard returns a fixed verdict and records the calls it saw.
type Guard struct {
	Verdict core.Verdict
	mu      sync.Mutex
	Calls   []core.ToolCall
}

func (g *Guard) Check(_ context.Context, c core.ToolCall, _ core.GuardContext) core.Verdict {
	g.mu.Lock()
	g.Calls = append(g.Calls, c)
	g.mu.Unlock()
	return g.Verdict
}

// Prober returns fixed states per model; unlisted models are FAIL/not_found.
type Prober struct {
	RuntimeName string
	States      map[string]core.ModelState
}

func (p Prober) Runtime() string { return p.RuntimeName }

func (p Prober) Probe(_ context.Context, candidates []string) ([]core.ProbeResult, error) {
	out := make([]core.ProbeResult, 0, len(candidates))
	for _, m := range candidates {
		st, ok := p.States[m]
		r := core.ProbeResult{Model: m, State: st}
		if !ok {
			r.State, r.Error = core.ModelFail, "not_found_error"
		}
		out = append(out, r)
	}
	return out, nil
}

// WorkerRunner returns scripted reports in order, then the last one forever.
type WorkerRunner struct {
	mu      sync.Mutex
	Reports []core.WorkerReport
	Specs   []core.WorkerSpec
}

func (w *WorkerRunner) Run(_ context.Context, s core.WorkerSpec) (core.WorkerReport, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Specs = append(w.Specs, s)
	if len(w.Reports) == 0 {
		return core.WorkerReport{}, fmt.Errorf("fakes.WorkerRunner: no scripted reports")
	}
	i := len(w.Specs) - 1
	if i >= len(w.Reports) {
		i = len(w.Reports) - 1
	}
	return w.Reports[i], nil
}

// Hosting serves files and reviews from maps.
type Hosting struct {
	Files    map[string][]byte // key "ref:path"
	ReadErr  error
	ReviewsM map[int][]core.Review
	Teams    map[string][]string
	Rules    json.RawMessage
	Opened   []core.PullRequest
}

func (h *Hosting) ReadFile(_ context.Context, ref, path string) ([]byte, error) {
	if h.ReadErr != nil {
		return nil, h.ReadErr
	}
	b, ok := h.Files[ref+":"+path]
	if !ok {
		return nil, fmt.Errorf("%s:%s: %w", ref, path, core.ErrNotFound)
	}
	return b, nil
}

func (h *Hosting) OpenDraftPR(_ context.Context, head, _, title, _ string) (core.PullRequest, error) {
	pr := core.PullRequest{Number: len(h.Opened) + 1, Author: "rr-app[bot]", URL: "fake://pr/" + head + "/" + title}
	h.Opened = append(h.Opened, pr)
	return pr, nil
}

func (h *Hosting) Reviews(_ context.Context, pr int) ([]core.Review, error) {
	return h.ReviewsM[pr], nil
}

func (h *Hosting) IsTeamMember(_ context.Context, team, login string) (bool, error) {
	for _, m := range h.Teams[team] {
		if m == login {
			return true, nil
		}
	}
	return false, nil
}

func (h *Hosting) Rulesets(context.Context, string) (json.RawMessage, error) { return h.Rules, nil }

// Runtime is a RuntimeAdapter that echoes a fixed ToolCall and records verdicts.
type Runtime struct {
	ID       string
	Call     core.ToolCall
	ParseErr error
	Gens     []core.Generator
	Enf      core.Enforcement
	Rendered []core.Verdict
}

func (r *Runtime) Name() string { return r.ID }

func (r *Runtime) ParseHookInput(event string, in io.Reader) (core.ToolCall, error) {
	_, _ = io.Copy(io.Discard, in)
	c := r.Call
	c.Runtime, c.Event = r.ID, event
	return c, r.ParseErr
}

func (r *Runtime) RenderHookOutput(_ string, _ core.ToolCall, v core.Verdict, stdout, _ io.Writer) (int, error) {
	r.Rendered = append(r.Rendered, v)
	_, err := fmt.Fprintf(stdout, "%s %s\n", v.Decision, v.Reason)
	if v.Decision == core.Allow || v.Decision == core.Ask {
		return 0, err
	}
	return 2, err
}

func (r *Runtime) Generators() []core.Generator { return r.Gens }

func (r *Runtime) Enforcement(context.Context, string) (core.Enforcement, error) {
	if r.Enf == "" {
		return core.EnforcementHookOnly, nil
	}
	return r.Enf, nil
}

// Generator renders fixed files.
type Generator struct {
	ID    string
	Files []core.File
}

func (g Generator) Name() string { return g.ID }

func (g Generator) Render(context.Context, core.SyncInput) ([]core.File, error) { return g.Files, nil }

// Parser returns fixed usage rows, ignoring input.
type Parser struct {
	RuntimeName string
	Rows        []core.Usage
}

func (p Parser) Runtime() string { return p.RuntimeName }

func (p Parser) Parse(r io.Reader) ([]core.Usage, error) {
	_, _ = io.Copy(io.Discard, r)
	return p.Rows, nil
}
