package autonomy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// DockerRunner runs one worker (claude -p or codex exec) in a throw-away Docker
// container and implements core.WorkerRunner. The checkout is bind-mounted at
// /work; riskrails.yaml, .git and .github are read-only on top of it (DES §3.4
// step 0; nothing of ~/.config/riskrails or ~/.cache/riskrails is mounted).
// The agent cannot commit: .git is read-only (errata #14, #17), the host does.
type DockerRunner struct {
	Bin     string // default "docker"
	Image   string // must contain the runtime CLI and rr
	Runtime string // claude | codex
	Root    string // host checkout, mounted at /work
	Sock    string // host halt socket, mounted for the hook ("" = none)
	Network string // the --internal network of Egress.Up; "" or "none" blocks the run
	// ProxyURL is the egress proxy on Network (HTTPS_PROXY in the agent).
	ProxyURL string
	// PolicyFile is the policy in force (riskrails.yaml from the default branch), a file
	// OUTSIDE the checkout, mounted read-only; the hook reads it via RR_POLICY_IN_FORCE.
	PolicyFile string
	// ScopeFile is the task's file list (JSON array), outside the checkout, mounted
	// read-only for the agent container (RR_SCOPE_FILE). "" = none.
	ScopeFile string
	noKeys    bool // Exec/CommandArgv: no API keys, no halt socket, no scope file
	Level     core.Level
	Models    map[core.Tier]string
	Timeout   time.Duration // 0 = 90 minutes
}

var (
	imageRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	modelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]*$`)
)

const (
	workDir  = "/work"
	sockPath = "/run/rr/halt.sock"
	// PolicyPath is where PolicyFile appears in the container.
	policyPath = "/run/rr/policy.yaml"
	scopePath  = "/run/rr/scope.json"
	readOnly   = "riskrails.yaml .git .github"
)

// argv builds the docker command; cmd runs inside the container.
func (d DockerRunner) argv(root, name, network string, stdin bool, cmd []string) ([]string, error) {
	if !imageRe.MatchString(d.Image) {
		return nil, fmt.Errorf("docker runner: image %q must be pinned by digest (name@sha256:<64 hex>)", d.Image)
	}
	switch {
	case network == "bridge", network == "host", network == "default", strings.HasPrefix(network, "container:"):
		return nil, fmt.Errorf("docker runner: the agent must never join network %q", network)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if d.PolicyFile == "" {
		return nil, fmt.Errorf("docker runner: no policy in force to mount (RR_POLICY_IN_FORCE)")
	}
	pol, err := outsideRoot(abs, d.PolicyFile)
	if err != nil {
		return nil, err
	}
	if err := requireRealGitDir(abs); err != nil {
		return nil, fmt.Errorf("docker runner: %w", err)
	}
	args := []string{"run", "--rm", "--pull", "never", "--name", name, "--network", network, "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "512",
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--tmpfs", "/tmp", "-e", "HOME=/tmp", "-w", workDir,
		"-e", "RR_LEVEL=" + d.Level.String()}
	args = append(args, d.envArgs(network)...)
	if stdin {
		args = append(args, "-i")
	}
	mounts := [][2]string{{abs, workDir}}
	for _, p := range strings.Fields(readOnly) {
		if _, err := os.Lstat(filepath.Join(abs, p)); err == nil {
			mounts = append(mounts, [2]string{filepath.Join(abs, p), workDir + "/" + p})
		}
	}
	for i, m := range mounts {
		if strings.Contains(m[0], ",") {
			return nil, fmt.Errorf("docker runner: path %q contains a comma", m[0])
		}
		opt := "type=bind,src=" + m[0] + ",dst=" + m[1]
		if i > 0 {
			opt += ",readonly"
		}
		args = append(args, "--mount", opt)
	}
	if strings.Contains(pol, ",") {
		return nil, fmt.Errorf("docker runner: path %q contains a comma", pol)
	}
	args = append(args, "--mount", "type=bind,src="+pol+",dst="+policyPath+",readonly", "-e", "RR_POLICY_IN_FORCE="+policyPath)
	if d.ScopeFile != "" {
		scope, err := outsideRoot(abs, d.ScopeFile)
		if err != nil {
			return nil, err
		}
		args = append(args, "--mount", "type=bind,src="+scope+",dst="+scopePath+",readonly", "-e", "RR_SCOPE_FILE="+scopePath)
	}
	if d.Sock != "" {
		args = append(args, "--mount", "type=bind,src="+d.Sock+",dst="+sockPath, "-e", "RR_HALT_SOCK="+sockPath)
	}
	return append(append(args, d.Image), cmd...), nil
}

// outsideRoot returns the absolute path of a runner-owned file that must not be
// inside the (agent-writable) checkout and must be mountable.
func outsideRoot(root, file string) (string, error) {
	p, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	if inside, err := within(root, filepath.Dir(p)); err != nil || inside {
		return "", fmt.Errorf("docker runner: %q must be outside the checkout (err: %v)", p, err) //nolint:errorlint // err may be nil
	}
	return p, nil
}

// envArgs: only the API key of the runtime that runs (none for Exec/CommandArgv),
// and the proxy settings when the container has a network.
func (d DockerRunner) envArgs(network string) (args []string) {
	if !d.noKeys {
		switch d.Runtime {
		case "claude":
			args = append(args, "-e", "ANTHROPIC_API_KEY")
		case "codex":
			args = append(args, "-e", "OPENAI_API_KEY")
		}
	}
	if d.ProxyURL != "" && network != "none" {
		for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
			args = append(args, "-e", k+"="+d.ProxyURL)
		}
		args = append(args, "-e", "NO_PROXY=localhost,127.0.0.1", "-e", "no_proxy=localhost,127.0.0.1", "-e", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1")
	}
	return args
}

// offline is the same sandbox for commands that are not the agent: no halt
// socket (it does not exist before Serve), no scope file, no API keys.
func (d DockerRunner) offline() DockerRunner {
	d.Sock, d.ScopeFile, d.noKeys = "", "", true
	return d
}

// Exec runs cmd in the same sandbox (no network) and returns its stdout.
func (d DockerRunner) Exec(ctx context.Context, cmd ...string) ([]byte, error) {
	name := "rr-close-" + randHex()
	args, err := d.offline().argv(d.Root, name, "none", false, cmd)
	if err != nil {
		return nil, err
	}
	bin := d.Bin
	if bin == "" {
		bin = "docker"
	}
	c := exec.CommandContext(ctx, bin, args...)
	c.Cancel = func() error {
		_ = exec.Command(bin, "kill", name).Run()
		return c.Process.Kill()
	}
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		_ = exec.Command(bin, "rm", "-f", name).Run()
		return out.Bytes(), fmt.Errorf("%s: %w: %s", strings.Join(cmd, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// CommandArgv is the argv (after the docker binary) that runs cmd in the same
// sandbox, for the close run (errata #26): W4-A hands it to verify as its runner.
func (d DockerRunner) CommandArgv(cmd ...string) ([]string, error) {
	return d.offline().argv(d.Root, "rr-close-"+randHex(), "none", false, cmd)
}

func (d DockerRunner) agentCmd(model string, maxTurns int) ([]string, error) {
	switch d.Runtime {
	case "claude":
		c := []string{"claude", "-p", "--output-format", "json", "--model", model, "--permission-mode", "dontAsk",
			"--permission-prompts", "none", "--no-session-persistence"}
		if maxTurns > 0 {
			c = append(c, "--max-turns", strconv.Itoa(maxTurns))
		}
		return c, nil
	case "codex":
		// never --dangerously-bypass-hook-trust: an untrusted hook would silently not run
		return []string{"codex", "exec", "--sandbox", "workspace-write", "-c", "approval_policy=never", "--ephemeral", "--json", "-m", model, "-"}, nil
	}
	return nil, fmt.Errorf("docker runner: unsupported runtime %q", d.Runtime)
}

func randHex() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run implements core.WorkerRunner. A worker that fails or prints no result is BLOCKED.
func (d DockerRunner) Run(ctx context.Context, spec core.WorkerSpec) (core.WorkerReport, error) {
	model, ok := d.Models[spec.Tier]
	if !ok {
		return core.WorkerReport{}, fmt.Errorf("docker runner: no model for tier %s", spec.Tier)
	}
	if !modelRe.MatchString(model) {
		return core.WorkerReport{}, fmt.Errorf("docker runner: model %q from the tiers lock is not a plain model id", model)
	}
	if d.Network == "" || d.Network == "none" || d.ProxyURL == "" {
		return core.WorkerReport{Status: core.StatusBlocked, Body: "no egress proxy for the runtime API (rr run --proxy-image)"}, nil
	}
	inner, err := d.agentCmd(model, spec.MaxTurns)
	if err != nil {
		return core.WorkerReport{}, err
	}
	root := d.Root
	if spec.Worktree != "" {
		root = spec.Worktree
	}
	name := "rr-" + randHex()
	args, err := d.argv(root, name, d.Network, true, inner)
	if err != nil {
		return core.WorkerReport{}, err
	}
	bin := d.Bin
	if bin == "" {
		bin = "docker"
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		_ = exec.Command(bin, "kill", name).Run() // the container outlives its client otherwise
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second
	cmd.Stdin = strings.NewReader(spec.Brief)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	if runErr != nil { // a failed or killed client may leave the container behind
		_ = exec.Command(bin, "rm", "-f", name).Run()
	}
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return parseReport(d.Runtime, out.String(), errb.String(), runErr), nil
}

func parseReport(runtime, stdout, stderr string, runErr error) core.WorkerReport {
	blocked := func(why string) core.WorkerReport {
		return core.WorkerReport{Status: core.StatusBlocked, Body: why + ": " + strings.TrimSpace(stderr)}
	}
	if runtime == "codex" {
		return parseCodex(stdout, stderr, runErr)
	}
	var res struct {
		Result   string         `json:"result"`
		IsError  bool           `json:"is_error"`
		NumTurns int            `json:"num_turns"`
		Usage    map[string]any `json:"usage"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		return blocked("claude: no JSON result")
	}
	var tokens int64
	for _, k := range []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"} {
		if v, ok := res.Usage[k].(float64); ok {
			tokens += int64(v)
		}
	}
	rep := core.WorkerReport{Status: statusOf(res.Result), Body: res.Result, Tokens: tokens, Calls: res.NumTurns}
	if res.IsError || runErr != nil {
		rep.Status = core.StatusBlocked
	}
	return rep
}

// parseCodex reads `codex exec --json` (docs/research/verified/runner.md): the
// last agent_message is the report, token usage is the sum of every
// turn.completed (input_tokens includes cached ones). A stream that does not
// parse, a turn without both numbers, or no turn.completed at all leaves Tokens
// at 0 = unknown, which the runner counts as over budget.
func parseCodex(stdout, stderr string, runErr error) core.WorkerReport {
	blocked := func(why string) core.WorkerReport {
		return core.WorkerReport{Status: core.StatusBlocked, Body: why + ": " + strings.TrimSpace(stderr)}
	}
	var msg string
	var tokens int64
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
			if ev.Usage.Input == nil || ev.Usage.Output == nil || *ev.Usage.Input < 0 || *ev.Usage.Output < 0 {
				known = false
				continue
			}
			tokens += *ev.Usage.Input + *ev.Usage.Output
		case "turn.failed":
			failed = true
		}
	}
	if !known || turns == 0 {
		tokens = 0
	}
	if runErr != nil {
		return blocked("codex: " + runErr.Error())
	}
	rep := core.WorkerReport{Status: statusOf(msg), Body: msg, Tokens: tokens, Calls: turns}
	if failed {
		rep.Status = core.StatusBlocked
	}
	return rep
}

// statusOf reads only the LAST non-empty line, which must be `STATUS: X`.
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
