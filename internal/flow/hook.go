package flow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/autonomy"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/policy"
)

// Hook is what the guard hook learns from the task in flight: its level and the
// files its scope allows (non-nil = scope guard armed).
type Hook struct {
	Task      string
	Level     core.Level
	StepFiles []string
}

// TaskHook reads the task in flight in root. ok=false: no task, nothing is armed.
// Any problem (two open tasks, unreadable journal, task_started without scope or
// level) is an error, which the caller turns into deny (fail-closed).
func TaskHook(ctx context.Context, root string, tree []string) (h Hook, ok bool, err error) {
	j := journal.New(root)
	open, err := j.Open(ctx)
	if err != nil {
		return Hook{}, false, err
	}
	switch len(open) {
	case 0:
		return Hook{}, false, nil
	case 1:
	default:
		return Hook{}, false, fmt.Errorf("%d tasks in flight in one checkout", len(open))
	}
	events, err := j.Events(ctx, open[0])
	if err != nil {
		return Hook{}, false, err
	}
	d, err := readStarted(events)
	if err != nil {
		return Hook{}, false, fmt.Errorf("task %s: %w", open[0], err)
	}
	if len(d.Scope) == 0 || d.Level == nil {
		return Hook{}, false, fmt.Errorf("task %s: task_started carries no scope or level", open[0])
	}
	// Armed even if nothing expands: Expand never returns nil for a non-empty scope.
	return Hook{Task: open[0], Level: *d.Level, StepFiles: Expand(d.Scope, tree)}, true, nil
}

// Env variables the runner (W4-B) sets in the container; they can only tighten.
const (
	EnvLevel    = "RR_LEVEL"
	EnvHaltSock = "RR_HALT_SOCK"
	EnvInForce  = "RR_POLICY_IN_FORCE"
)

// TightenLevel applies RR_LEVEL: a level ≥ L2 turns ask into deny; anything
// lower never loosens the host session's level. A set but invalid value is an error.
func TightenLevel(cur core.Level, getenv func(string) (string, bool)) (core.Level, error) {
	v, set := getenv(EnvLevel)
	if !set {
		return cur, nil
	}
	var l core.Level
	if err := l.UnmarshalText([]byte(v)); err != nil {
		return cur, fmt.Errorf("%s: %w", EnvLevel, err)
	}
	if l >= core.L2 && l > cur {
		return l, nil
	}
	return cur, nil
}

// CheckHalt asks the runner's halt socket (RR_HALT_SOCK, protocol of
// autonomy.Halter.Serve: one line "ok" or "halt <reason>" per connection). An
// unreachable socket or any answer but "ok" is an error: deny.
func CheckHalt(getenv func(string) (string, bool)) error {
	p, set := getenv(EnvHaltSock)
	if !set {
		return nil
	}
	if p == "" {
		return fmt.Errorf("%s is set but empty", EnvHaltSock)
	}
	if r := (autonomy.Client{Path: p}).Halted(); r != "" {
		return fmt.Errorf("halted: %s", r)
	}
	return nil
}

const maxPolicyBytes = 1 << 20

// InForceFromEnv reads RR_POLICY_IN_FORCE: the raw riskrails.yaml of the default
// branch, read by the runner through the Hosting API and mounted read-only. It is
// the DefaultBranch layer. The file must be absolute and outside root (inside the
// checkout the agent could have written it); a missing or invalid file is an error.
func InForceFromEnv(root string, getenv func(string) (string, bool)) (*core.Layer, error) {
	p, set := getenv(EnvInForce)
	if !set {
		return nil, nil
	}
	if !filepath.IsAbs(p) {
		return nil, fmt.Errorf("%s: %q is not an absolute path", EnvInForce, p)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvInForce, err)
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(rootReal, real); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s: %s is inside the checkout", EnvInForce, p)
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvInForce, err)
	}
	if len(raw) > maxPolicyBytes {
		return nil, fmt.Errorf("%s: over %d bytes", EnvInForce, maxPolicyBytes)
	}
	pol, err := policy.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvInForce, err)
	}
	return &core.Layer{Policy: pol, Raw: raw, Source: "env:" + EnvInForce}, nil
}
