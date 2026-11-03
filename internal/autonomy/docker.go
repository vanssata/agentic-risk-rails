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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
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
	// CodexConfig is the user config (StateDir, outside the checkout) that marks /work
	// trusted: mounted read-only at $HOME/.codex/config.toml (codex only).
	CodexConfig string
	// CeilingEnt / CeilingUser are the ceiling files the host resolved with (StateDir
	// copies, "" or absent = none): mounted read-only where the guard in the container
	// looks for them (HOME=/tmp).
	CeilingEnt, CeilingUser string
	// NoRead are the repo-relative patterns of enforcement.secret_reads and
	// sandbox.no_read (already expanded): every match in the checkout, git-ignored or
	// not, is masked in the container.
	NoRead []string
	// ROPaths are the repo-relative patterns of enforcement.protected_paths,
	// sandbox.readonly and sandbox.no_write: every existing match is bind-mounted
	// read-only over itself. The runtimes' own sandboxes cannot start in the
	// container (bwrap needs user namespaces), so the container enforces them
	// (errata #42); a new file matching one is caught by the host-side close scope.
	ROPaths []string
	// AuthFrom is an isolated subscription login dir (e.g. ~/.claude-rr, ~/.codex-rr):
	// its credentials file is copied per agent container into a fresh dir under
	// StateDir, mounted as the runtime's config dir (stageAuth). "" = API key only.
	AuthFrom string
	StateDir string // runner-owned, outside the checkout
	authDir  string // the staged login of this container
	noKeys   bool   // Exec/CommandArgv: no API keys, no login, no halt socket, no scope file
	ro       bool   // ReadOnly(): /work is mounted read-only
	wt       bool   // the mounted root is a step worktree: its .git is a file (stays read-only)
	env      []string
	Level    core.Level
	Models   map[core.Tier]string
	Timeout  time.Duration // 0 = 90 minutes
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
	// the container's HOME is /tmp
	codexHome       = "/tmp/.codex"
	ceilingEntPath  = "/etc/riskrails/ceiling.yaml"
	ceilingUserPath = "/tmp/.config/riskrails/ceiling.yaml"
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
	if err := d.checkGit(abs); err != nil {
		return nil, fmt.Errorf("docker runner: %w", err)
	}
	args := []string{"run", "--rm", "--init", "--pull", "never", "--name", name, "--network", network, "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--pids-limit", "512",
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev", // exec: go test runs its binary from /tmp
		"-e", "HOME=/tmp", "-w", workDir,
		"-e", "RR_LEVEL=" + d.Level.String()}
	args = append(args, d.envArgs(network)...)
	if stdin {
		args = append(args, "-i")
	}
	mounts := [][2]string{{abs, workDir}}
	for _, p := range readOnlyPaths() {
		if _, err := os.Lstat(filepath.Join(abs, p)); err == nil {
			mounts = append(mounts, [2]string{filepath.Join(abs, p), workDir + "/" + p})
		}
	}
	for i, m := range mounts {
		if strings.Contains(m[0], ",") {
			return nil, fmt.Errorf("docker runner: path %q contains a comma", m[0])
		}
		args = append(args, "--mount", bindOpt(m[0], m[1], i > 0 || d.ro))
	}
	args = append(args, "-e", "RR_POLICY_IN_FORCE="+policyPath)
	files := [][2]string{{pol, policyPath}}
	if d.ScopeFile != "" {
		scope, err := outsideRoot(abs, d.ScopeFile)
		if err != nil {
			return nil, err
		}
		files = append(files, [2]string{scope, scopePath})
		args = append(args, "-e", "RR_SCOPE_FILE="+scopePath)
	}
	for _, f := range files {
		if strings.Contains(f[0], ",") {
			return nil, fmt.Errorf("docker runner: path %q contains a comma", f[0])
		}
		args = append(args, "--mount", bindOpt(f[0], f[1], true))
	}
	for _, e := range d.env {
		args = append(args, "-e", e)
	}
	extra, err := d.configMounts(abs)
	if err != nil {
		return nil, err
	}
	args = append(args, extra...)
	if d.Sock != "" {
		args = append(args, "--mount", "type=bind,src="+d.Sock+",dst="+sockPath, "-e", "RR_HALT_SOCK="+sockPath)
	}
	return append(append(args, d.Image), cmd...), nil
}

// checkGit: the checkout needs a real .git directory, a step worktree a .git file.
func (d DockerRunner) checkGit(root string) error {
	if d.wt {
		return requireGitEntry(root)
	}
	return requireRealGitDir(root)
}

func bindOpt(src, dst string, ro bool) string {
	opt := "type=bind,src=" + src + ",dst=" + dst
	if ro {
		opt += ",readonly"
	}
	return opt
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

// readOnlyPaths are the concrete paths of core.AlwaysProtected (the agent has no
// business writing them; the journal lives in the runner's StateDir) that exist
// get a read-only mount over the writable checkout.
func readOnlyPaths() []string {
	var out []string
	for _, p := range core.AlwaysProtected {
		p = strings.TrimSuffix(p, "/**")
		if !strings.ContainsAny(p, "*?[{") {
			out = append(out, p)
		}
	}
	return out
}

// ReadOnly implements factory.ReadOnlyRunner: the same container with /work mounted
// read-only (reviewers, scouts, planner).
func (d DockerRunner) ReadOnly() core.WorkerRunner {
	d.ro = true
	return d
}

var envKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// withEnv applies WorkerSpec.Env: RR_SCOPE_FILE becomes the read-only scope mount
// (its path in the container is scopePath); the rest is passed as given. A key that
// argv sets itself (HOME, RR_*, credentials, proxies) is refused, not overridden.
func (d DockerRunner) withEnv(env []string) (DockerRunner, error) {
	d.env = nil
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !envKeyRe.MatchString(k) {
			return d, fmt.Errorf("docker runner: env %q is not KEY=VALUE", k)
		}
		switch {
		case k == "RR_SCOPE_FILE":
			if v == "" {
				return d, fmt.Errorf("docker runner: RR_SCOPE_FILE is empty")
			}
			d.ScopeFile = v
		case k == "RR_WORKER":
			d.env = append(d.env, kv)
		case strings.HasPrefix(k, "RR_"), k == "HOME", k == "PATH", strings.HasSuffix(k, "_PROXY"), strings.HasPrefix(k, "CLAUDE_"),
			strings.HasPrefix(k, "ANTHROPIC_"), strings.HasPrefix(k, "OPENAI_"), strings.HasPrefix(k, "CODEX_"):
			return d, fmt.Errorf("docker runner: env %s is set by the runner and cannot be overridden", k)
		default:
			d.env = append(d.env, kv)
		}
	}
	return d, nil
}

// Probe runs cmd as the agent would see it (halt socket, scope file) but without
// network and API keys, and returns its stdout.
func (d DockerRunner) Probe(ctx context.Context, cmd ...string) ([]byte, error) {
	d.noKeys = true
	return d.runOnce(ctx, cmd)
}

// Exec runs cmd in the same sandbox (no network, no socket, no keys) and returns its stdout.
func (d DockerRunner) Exec(ctx context.Context, cmd ...string) ([]byte, error) {
	return d.offline().runOnce(ctx, cmd)
}

func (d DockerRunner) runOnce(ctx context.Context, cmd []string) ([]byte, error) {
	name := "rr-close-" + randHex()
	args, err := d.argv(d.Root, name, "none", false, cmd)
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

// CloseSandbox is the verify.Sandbox of the host-side close: every adapter command
// runs in its own named, offline container. cleanup force-removes them all; call it
// when the close returns or is cancelled (docker run's client dying does not stop
// the container).
func (d DockerRunner) CloseSandbox() (sandbox func([]string) ([]string, error), cleanup func(context.Context)) {
	var mu sync.Mutex
	var names []string
	sandbox = func(argv []string) ([]string, error) {
		name := "rr-close-" + randHex()
		a, err := d.offline().argv(d.Root, name, "none", false, argv)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		names = append(names, name)
		mu.Unlock()
		return append([]string{"docker"}, a...), nil
	}
	cleanup = func(ctx context.Context) {
		bin := d.Bin
		if bin == "" {
			bin = "docker"
		}
		mu.Lock()
		defer mu.Unlock()
		for _, n := range names {
			_ = exec.CommandContext(context.WithoutCancel(ctx), bin, "rm", "-f", n).Run() // absent (--rm) is fine
		}
	}
	return sandbox, cleanup
}

func (d DockerRunner) agentCmd(model string, maxTurns int) ([]string, error) {
	switch d.Runtime {
	case "claude":
		// The project settings rendered at L>=2 require claude's own OS sandbox, which
		// cannot start under --cap-drop ALL; in the container the container is the
		// sandbox (errata #42). --settings sits above project settings
		// (docs/research/verified/claude-code.md); hooks and permissions stay.
		c := []string{"claude", "-p", "--output-format", "json", "--model", model, "--permission-mode", "dontAsk",
			"--permission-prompts", "none", "--no-session-persistence", "--settings", `{"sandbox":{"enabled":false}}`}
		if maxTurns > 0 {
			c = append(c, "--max-turns", strconv.Itoa(maxTurns))
		}
		return c, nil
	case "codex":
		// never --dangerously-bypass-hook-trust: an untrusted hook would silently not run.
		// danger-full-access: codex's bwrap cannot start in the container, which is the
		// sandbox (errata #42: ro protected paths, masked secrets, egress proxy only).
		return []string{"codex", "exec", "--sandbox", "danger-full-access", "-c", "approval_policy=never", "--ephemeral", "--json", "-m", model, "-"}, nil
	}
	return nil, fmt.Errorf("docker runner: unsupported runtime %q", d.Runtime)
}

func randHex() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run implements core.WorkerRunner. A worker that fails or prints no result is BLOCKED.
func (d DockerRunner) Run(ctx context.Context, spec core.WorkerSpec) (rep core.WorkerReport, err error) {
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
	if d.AuthFrom != "" {
		dir, done, serr := d.stageAuth()
		if serr != nil {
			return core.WorkerReport{}, serr
		}
		d.authDir = dir
		defer func() {
			if derr := done(); derr != nil && err == nil {
				err = derr
			}
		}()
	}
	root := d.Root
	if spec.Worktree != "" {
		root = spec.Worktree
		d.wt = filepath.Clean(root) != filepath.Clean(d.Root)
	}
	if d, err = d.withEnv(spec.Env); err != nil {
		return core.WorkerReport{}, err
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
	return parseReport(d.Runtime, model, out.String(), errb.String(), runErr), nil
}

// parseReport reads the worker's stdout. Usage carries the model (claude: the one
// that handled most tokens in modelUsage, errata #63; else the --model value), so
// the budget and the ledger price it; absent usage stays zero = unknown.
func parseReport(runtime, model, stdout, stderr string, runErr error) core.WorkerReport {
	blocked := func(why string) core.WorkerReport {
		return core.WorkerReport{Status: core.StatusBlocked, Body: why + ": " + strings.TrimSpace(stderr)}
	}
	if runtime == "codex" {
		return parseCodex(model, stdout, stderr, runErr)
	}
	var res struct {
		Result     string         `json:"result"`
		IsError    bool           `json:"is_error"`
		NumTurns   int            `json:"num_turns"`
		Usage      map[string]any `json:"usage"`
		ModelUsage map[string]struct {
			In  int64 `json:"inputTokens"`
			Out int64 `json:"outputTokens"`
		} `json:"modelUsage"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		return blocked("claude: no JSON result")
	}
	num := func(k string) int64 { v, _ := res.Usage[k].(float64); return int64(v) }
	in, out, cr, cw := num("input_tokens"), num("output_tokens"), num("cache_read_input_tokens"), num("cache_creation_input_tokens")
	rep := core.WorkerReport{Status: statusOf(res.Result), Body: res.Result, Tokens: in + out + cr + cw, Calls: res.NumTurns}
	if _, ok := res.Usage["input_tokens"]; ok && min(in, out, cr, cw) >= 0 { // no token count = unknown, never free
		best, bestN := model, int64(-1)
		for m, u := range res.ModelUsage {
			if n := u.In + u.Out; n > bestN || (n == bestN && m < best) {
				best, bestN = m, n
			}
		}
		rep.Usage = core.Usage{Runtime: "claude", Model: best, Time: time.Now().UTC(), Input: in, Output: out, CacheRead: cr, CacheWrite: cw}
	}
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
func parseCodex(model, stdout, stderr string, runErr error) core.WorkerReport {
	blocked := func(why string) core.WorkerReport {
		return core.WorkerReport{Status: core.StatusBlocked, Body: why + ": " + strings.TrimSpace(stderr)}
	}
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
	if runErr != nil {
		return blocked("codex: " + runErr.Error())
	}
	rep := core.WorkerReport{Status: statusOf(msg), Body: msg, Calls: turns}
	if known && turns > 0 {
		rep.Tokens = in + out
		rep.Usage = core.Usage{Runtime: "codex", Model: model, Time: time.Now().UTC(), Input: in - cached, Output: out, CacheRead: cached}
	}
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

// secretMasks walks the checkout (git-ignored files included, .git excluded) and
// returns the --mount args that hide every path matching a no-read pattern: an empty
// read-only tmpfs over a directory, /dev/null over a file. Home and absolute
// patterns are outside the checkout. A tree that cannot be walked is an error.
func secretMasks(root string, patterns []string) (args []string, err error) {
	err = walkMatches(root, patterns, []string{".git"}, func(rel string, dir bool) {
		if dir {
			args = append(args, "--mount", "type=tmpfs,dst="+workDir+"/"+rel+",tmpfs-size=4096,readonly")
			return
		}
		args = append(args, "--mount", "type=bind,src=/dev/null,dst="+workDir+"/"+rel+",readonly")
	})
	return args, err
}

// protectedMounts bind-mounts every existing match read-only over itself; paths
// under the AlwaysProtected mounts are read-only already.
func protectedMounts(root string, patterns []string) (args []string, err error) {
	err = walkMatches(root, patterns, append([]string{".git"}, readOnlyPaths()...), func(rel string, _ bool) {
		args = append(args, "--mount", "type=bind,src="+filepath.Join(root, rel)+",dst="+workDir+"/"+rel+",readonly")
	})
	return args, err
}

// walkMatches walks the checkout (git-ignored files included, the skip paths
// excluded) and calls fn for each path matching a repo-relative pattern; a
// matching dir is not descended.
func walkMatches(root string, patterns, skip []string, fn func(rel string, dir bool)) error {
	var pats []string
	for _, p := range patterns {
		if !strings.HasPrefix(p, "~") && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "$") {
			pats = append(pats, p)
		}
	}
	if len(pats) == 0 {
		return nil
	}
	return filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", p, err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if slices.Contains(skip, rel) {
			if e.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !slices.ContainsFunc(pats, func(pat string) bool { return globs.Match(pat, rel) }) {
			return nil
		}
		if strings.Contains(rel, ",") {
			return fmt.Errorf("path %q contains a comma", rel)
		}
		fn(rel, e.IsDir())
		if e.IsDir() {
			return fs.SkipDir
		}
		return nil
	})
}

// configMounts are the read-only runner-owned config files and the secret masks.
func (d DockerRunner) configMounts(abs string) (args []string, err error) {
	for _, f := range []struct{ src, dst string }{{d.CeilingEnt, ceilingEntPath}, {d.CeilingUser, ceilingUserPath}} {
		if _, err := os.Stat(f.src); f.src == "" || err != nil {
			continue
		}
		if strings.Contains(f.src, ",") {
			return nil, fmt.Errorf("docker runner: path %q contains a comma", f.src)
		}
		args = append(args, "--mount", "type=bind,src="+f.src+",dst="+f.dst+",readonly")
	}
	login := d.authDir != "" && !d.noKeys
	if login && strings.Contains(d.authDir, ",") {
		return nil, fmt.Errorf("docker runner: path %q contains a comma", d.authDir)
	}
	if login && d.Runtime == "claude" {
		args = append(args, "--mount", "type=bind,src="+d.authDir+",dst="+claudeHome, "-e", "CLAUDE_CONFIG_DIR="+claudeHome)
	}
	if d.Runtime == "codex" && d.CodexConfig != "" {
		if strings.Contains(d.CodexConfig, ",") {
			return nil, fmt.Errorf("docker runner: path %q contains a comma", d.CodexConfig)
		}
		if login { // the staged login is the codex home
			args = append(args, "--mount", "type=bind,src="+d.authDir+",dst="+codexHome)
		} else { // a tmpfs owned by the agent user, so codex can write its state
			args = append(args, "--tmpfs", codexHome+":rw,mode=0700,uid="+strconv.Itoa(os.Getuid())+",gid="+strconv.Itoa(os.Getgid()))
		}
		// the trust config is read-only on top
		args = append(args, "--mount", "type=bind,src="+d.CodexConfig+",dst="+codexHome+"/config.toml,readonly")
	}
	ro, err := protectedMounts(abs, d.ROPaths)
	if err != nil {
		return nil, fmt.Errorf("docker runner: %w", err)
	}
	masks, err := secretMasks(abs, d.NoRead)
	if err != nil {
		return nil, fmt.Errorf("docker runner: %w", err)
	}
	args = append(append(args, ro...), masks...) // masks last: a protected secret stays unreadable
	return args, nil
}
