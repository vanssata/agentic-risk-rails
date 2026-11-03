package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// ClaudeRunner runs a worker as `claude -p` with cwd = the step worktree.
// Models maps a tier to the alias/ID passed to --model (from EffectiveTiers).
type ClaudeRunner struct {
	Bin      string // default "claude"
	Models   map[core.Tier]string
	readOnly bool // set by ReadOnly(): reviewers get a read-only tool allowlist
	// DenyRead: permission rules (e.g. "Read(.env)") added to a read-only worker's
	// --disallowedTools; it loads user settings only, so the project's Read denies
	// (secret_reads, no_read) do not reach it otherwise. Empty = none.
	DenyRead []string
	Timeout  time.Duration // per worker; 0 = DefaultTimeout, never unlimited
}

// DefaultTimeout bounds a worker that has no explicit Timeout.
const DefaultTimeout = 30 * time.Minute

// claudeResult is the subset of the `--output-format json` result object used
// (fields confirmed against claude 2.1.316).
type claudeResult struct {
	Result   string         `json:"result"`
	IsError  bool           `json:"is_error"`
	NumTurns int            `json:"num_turns"`
	RawUsage map[string]any `json:"usage"`
	// ModelUsage is keyed by the actual model IDs used.
	ModelUsage map[string]struct {
		In  int64 `json:"inputTokens"`
		Out int64 `json:"outputTokens"`
	} `json:"modelUsage"`
}

// ReadOnly returns a copy that can only read: plan mode, a Read/Grep/Glob tool
// allowlist, user-level settings only and no MCP servers.
func (c ClaudeRunner) ReadOnly() core.WorkerRunner {
	c.readOnly = true
	return c
}

func (c ClaudeRunner) Run(ctx context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	model, ok := c.Models[spec.Tier]
	if !ok {
		return core.WorkerReport{}, fmt.Errorf("claude runner: no model for tier %s", spec.Tier)
	}
	bin, mode := c.Bin, "acceptEdits"
	if bin == "" {
		bin = "claude"
	}
	if c.readOnly {
		// not "plan": claude 2.1.317 runs `--model haiku` as Sonnet in plan mode
		// (errata #63). Read-only is the tool allowlist below, not the mode.
		mode = "default"
	}
	args := []string{"-p", "--output-format", "json", "--model", model, "--permission-mode", mode, "--no-session-persistence"}
	if spec.MaxTurns > 0 {
		args = append(args, "--max-turns", strconv.Itoa(spec.MaxTurns))
	}
	if c.readOnly {
		// allowlist of read tools; project/local settings and MCP servers are
		// worker-writable (even when git-ignored), so only user settings load.
		args = append(args, "--tools", "Read,Grep,Glob", "--disallowedTools", "Edit,Write,MultiEdit,NotebookEdit,Bash")
		args = append(args, c.DenyRead...)
		args = append(args, "--setting-sources", "user", "--strict-mcp-config")
	}
	stdout, stderr, runErr := runProc(ctx, bin, args, spec, c.Timeout)

	var res claudeResult
	if err := json.Unmarshal(stdout, &res); err != nil {
		// no parsable result: the worker failed, never a success
		return core.WorkerReport{Status: core.StatusBlocked, Body: "claude: no JSON result: " + strings.TrimSpace(stderr)}, nil //nolint:nilerr
	}
	num := func(k string) int64 { v, _ := res.RawUsage[k].(float64); return int64(v) }
	in, out, cr, cw := num("input_tokens"), num("output_tokens"), num("cache_read_input_tokens"), num("cache_creation_input_tokens")
	rep := core.WorkerReport{Status: statusOf(res.Result), Body: res.Result, Tokens: in + out + cr + cw, Calls: res.NumTurns}
	if len(res.RawUsage) > 0 { // absent usage stays zero = unknown, never free
		rep.Usage = core.Usage{Runtime: "claude", Model: res.mainModel(model), Time: time.Now().UTC(), Input: in, Output: out, CacheRead: cr, CacheWrite: cw}
	}
	if res.IsError || runErr != nil { // e.g. --max-turns reached
		rep.Status = core.StatusBlocked
	}
	return rep, nil
}

// mainModel is the model that handled most tokens, else the --model value.
func (r claudeResult) mainModel(fallback string) string {
	best, bestN := fallback, int64(-1)
	for m, u := range r.ModelUsage {
		if n := u.In + u.Out; n > bestN || (n == bestN && m < best) {
			best, bestN = m, n
		}
	}
	return best
}

// runProc runs bin in spec.Worktree with the brief on stdin and spec.Env added
// to the inherited environment. It is bounded by timeout (0 = DefaultTimeout)
// and kills the whole process group, also leftovers after a normal exit.
func runProc(ctx context.Context, bin string, args []string, spec core.WorkerSpec, timeout time.Duration) (stdout []byte, stderr string, runErr error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) } // the whole group
	cmd.WaitDelay = time.Second
	cmd.Dir = spec.Worktree
	cmd.Env = append(os.Environ(), spec.Env...)
	cmd.Stdin = strings.NewReader(spec.Brief)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr = cmd.Run()
	if cmd.Process != nil { // leftover background processes die with the worker
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return out.Bytes(), errb.String(), runErr
}

// statusOf reads only the LAST non-empty line, which must be `STATUS: X`;
// anything else is BLOCKED (a status quoted earlier in the body does not count).
func statusOf(body string) core.WorkerStatus {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	v, ok := strings.CutPrefix(strings.TrimSpace(lines[len(lines)-1]), "STATUS:")
	if !ok {
		return core.StatusBlocked
	}
	switch s := core.WorkerStatus(strings.TrimSpace(v)); s {
	case core.StatusDone, core.StatusDoneWithConcerns, core.StatusNeedsContext:
		return s
	}
	return core.StatusBlocked
}
