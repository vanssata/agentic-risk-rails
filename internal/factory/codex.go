package factory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// CodexRunner runs a worker as `codex exec` with cwd = the step worktree.
// Models maps a tier to the model passed to --model (from EffectiveTiers).
// codex exec has no turn limit flag: spec.MaxTurns is not enforced, only Timeout.
type CodexRunner struct {
	Bin      string // default "codex"
	Models   map[core.Tier]string
	readOnly bool          // set by ReadOnly(): reviewers and scouts cannot write
	Timeout  time.Duration // per worker; 0 = DefaultTimeout, never unlimited
}

// withGoCache puts the Go build cache where workspace-write can write (it cannot under HOME,
// errata #65) unless env already sets GOCACHE.
func withGoCache(env []string) []string {
	for _, e := range env {
		if strings.HasPrefix(e, "GOCACHE=") {
			return env
		}
	}
	return append(env[:len(env):len(env)], fmt.Sprintf("GOCACHE=%s/rr-gocache-%d", os.TempDir(), os.Getuid()))
}

// ReadOnly returns a copy that can only read.
func (c CodexRunner) ReadOnly() core.WorkerRunner {
	c.readOnly = true
	return c
}

func (c CodexRunner) Run(ctx context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	model, ok := c.Models[spec.Tier]
	if !ok {
		return core.WorkerReport{}, fmt.Errorf("codex runner: no model for tier %s", spec.Tier)
	}
	bin, sandbox := c.Bin, "workspace-write"
	if bin == "" {
		bin = "codex"
	}
	if c.readOnly {
		sandbox = "read-only"
	}
	// the trailing "-" reads the prompt from stdin
	args := []string{"exec", "--json", "--ephemeral", "--sandbox", sandbox, "--model", model, "-"}
	spec.Env = withGoCache(spec.Env)
	stdout, stderr, runErr := runProc(ctx, bin, args, spec, c.Timeout)
	if runErr != nil {
		return core.WorkerReport{Status: core.StatusBlocked, Body: "codex: " + runErr.Error() + ": " + strings.TrimSpace(stderr)}, nil //nolint:nilerr
	}
	return parseCodex(string(stdout), model), nil
}

// parseCodex reads `codex exec --json` (docs/research/verified/workers.md): the
// last agent_message is the report; usage is the sum of every turn.completed.
// input_tokens includes cached ones, so Usage.Input is the uncached remainder.
// A broken stream, a turn without input/output numbers or no turn.completed
// leaves Tokens and Usage zero = unknown (never priced as free).
// Minimal copy of autonomy.parseCodex (unexported, and that package carries
// the docker runner).
func parseCodex(stdout, model string) core.WorkerReport {
	var msg string
	var in, cached, out int64
	var turns int
	known, failed := true, false
	dec := json.NewDecoder(strings.NewReader(stdout))
	for {
		var ev struct {
			Type string `json:"type"`
			Item struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"item"`
			Usage struct {
				Input  *int64 `json:"input_tokens"`
				Cached int64  `json:"cached_input_tokens"`
				Output *int64 `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := dec.Decode(&ev); err != nil {
			known = known && errors.Is(err, io.EOF)
			break
		}
		switch ev.Type {
		case "item.completed":
			if ev.Item.Type == "agent_message" {
				msg = ev.Item.Text
			}
		case "turn.completed":
			turns++
			u := ev.Usage
			if u.Input == nil || u.Output == nil || *u.Input < 0 || *u.Output < 0 || u.Cached < 0 || u.Cached > *u.Input {
				known = false
				continue
			}
			in, cached, out = in+*u.Input, cached+u.Cached, out+*u.Output
		case "turn.failed":
			failed = true
		}
	}
	rep := core.WorkerReport{Status: statusOf(msg), Body: msg, Calls: turns}
	if msg == "" || failed {
		rep.Status = core.StatusBlocked
	}
	if known && turns > 0 {
		rep.Tokens = in + out
		rep.Usage = core.Usage{Runtime: "codex", Model: model, Time: time.Now().UTC(), Input: in - cached, Output: out, CacheRead: cached}
	}
	return rep
}
