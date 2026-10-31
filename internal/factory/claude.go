package factory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	readOnly bool          // set by ReadOnly(): reviewers get a read-only tool allowlist
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
		mode = "plan"
	}
	args := []string{"-p", "--output-format", "json", "--model", model, "--permission-mode", mode, "--no-session-persistence"}
	if spec.MaxTurns > 0 {
		args = append(args, "--max-turns", strconv.Itoa(spec.MaxTurns))
	}
	if c.readOnly {
		// allowlist of read tools; project/local settings and MCP servers are
		// worker-writable (even when git-ignored), so only user settings load.
		args = append(args, "--tools", "Read,Grep,Glob", "--disallowedTools", "Edit,Write,MultiEdit,NotebookEdit,Bash",
			"--setting-sources", "user", "--strict-mcp-config")
	}
	timeout := c.Timeout
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
	cmd.Stdin = strings.NewReader(spec.Brief)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	if cmd.Process != nil { // leftover background processes die with the worker, also after a normal exit
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	var res claudeResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		// no parsable result: the worker failed, never a success
		return core.WorkerReport{Status: core.StatusBlocked, Body: "claude: no JSON result: " + strings.TrimSpace(errb.String())}, nil //nolint:nilerr
	}
	var tokens int64
	for _, k := range []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"} {
		if v, ok := res.RawUsage[k].(float64); ok {
			tokens += int64(v)
		}
	}
	rep := core.WorkerReport{Status: statusOf(res.Result), Body: res.Result, Tokens: tokens, Calls: res.NumTurns}
	if res.IsError || runErr != nil { // e.g. --max-turns reached
		rep.Status = core.StatusBlocked
	}
	return rep, nil
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
