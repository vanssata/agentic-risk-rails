package autonomy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	Level   core.Level
	Models  map[core.Tier]string
	Timeout time.Duration // 0 = 90 minutes
}

const (
	workDir  = "/work"
	sockPath  = "/run/rr/halt.sock"
	readOnly = "riskrails.yaml .git .github"
)

// argv builds the docker command; cmd runs inside the container.
func (d DockerRunner) argv(root, name string, stdin bool, cmd []string) ([]string, error) {
	if d.Image == "" {
		return nil, fmt.Errorf("docker runner: no image")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(filepath.Join(abs, ".git"))
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("docker runner: %s/.git must be a real directory (a worktree .git file would stay writable)", abs)
	}
	args := []string{"run", "--rm", "--name", name, "--network", "none", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "512",
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--tmpfs", "/tmp", "-e", "HOME=/tmp", "-w", workDir,
		"-e", "RR_LEVEL=" + d.Level.String(), "-e", "ANTHROPIC_API_KEY", "-e", "OPENAI_API_KEY"}
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
	if d.Sock != "" {
		args = append(args, "--mount", "type=bind,src="+d.Sock+",dst="+sockPath, "-e", "RR_HALT_SOCK="+sockPath)
	}
	return append(append(args, d.Image), cmd...), nil
}

// CommandArgv is the argv (after the docker binary) that runs cmd in the same
// sandbox, for the close run (errata #26): W4-A hands it to verify as its runner.
func (d DockerRunner) CommandArgv(cmd ...string) ([]string, error) {
	return d.argv(d.Root, "rr-close-"+randHex(), false, cmd)
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
		return []string{"codex", "exec", "--sandbox", "workspace-write", "-c", "approval_policy=never", "--ephemeral", "-m", model, "-"}, nil
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
	inner, err := d.agentCmd(model, spec.MaxTurns)
	if err != nil {
		return core.WorkerReport{}, err
	}
	root := d.Root
	if spec.Worktree != "" {
		root = spec.Worktree
	}
	name := "rr-" + randHex()
	args, err := d.argv(root, name, true, inner)
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
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return parseReport(d.Runtime, out.String(), errb.String(), runErr), nil
}

func parseReport(runtime, stdout, stderr string, runErr error) core.WorkerReport {
	blocked := func(why string) core.WorkerReport {
		return core.WorkerReport{Status: core.StatusBlocked, Body: why + ": " + strings.TrimSpace(stderr)}
	}
	if runtime == "codex" { // final message on stdout, no token count
		if runErr != nil {
			return blocked("codex: " + runErr.Error())
		}
		return core.WorkerReport{Status: statusOf(stdout), Body: stdout}
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
