package autonomy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/gitx"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
	rrsync "github.com/vanssata/agentic-risk-rails/internal/sync"
	"github.com/vanssata/agentic-risk-rails/internal/triage"
)

// Task is one queue item. Mode and Irreversible come from triage (declared here
// until `rr task` wires the real weight, W4-A).
type Task struct {
	ID           string    `yaml:"id"`
	Brief        string    `yaml:"brief"`
	Mode         core.Mode `yaml:"mode"` // default light
	Irreversible bool      `yaml:"irreversible"`
	Tier         core.Tier `yaml:"tier"` // default BALANCED
	MaxTurns     int       `yaml:"max_turns"`
	Files        []string  `yaml:"files"` // declared scope; handed to the agent's hook read-only
}

// Outcome is what happened to one queue item.
type Outcome struct {
	Task   string
	Level  core.Level
	Status string // pr | skipped | blocked | empty
	PR     core.PullRequest
}

// Runner is the unattended runner (DES §8.2): a process OUTSIDE the agent
// sandbox. Every failure to establish a safety fact is a refusal or a halt.
type Runner struct {
	Root          string // checkout the container mounts; must be clean
	StateDir      string // runner-owned, outside the sandbox: journal copies, day counter
	RunID         string
	DefaultBranch string
	Level         core.Level // requested, ≥ L2
	Container     bool       // the Worker runs in a container
	Runtime       core.RuntimeAdapter
	Hosting       core.Hosting
	Journal       core.Journal // the runner's own, authoritative
	Worker        core.WorkerRunner
	// Resolve resolves the policy with `inForce` (riskrails.yaml read from the
	// default branch through the hosting API) as the DefaultBranch layer and
	// the ceiling files; the working tree is never a layer at L≥2.
	Resolve  func(ctx context.Context, inForce []byte) (core.EffectivePolicy, error)
	Gens     []core.Generator
	Tiers    map[string]core.EffectiveTiers
	Home     string
	Clock    Clock
	HaltSock string // unix socket for the hooks; "" = none
	// Exec runs a command in the agent's container image (no network): the
	// enforcement probe and the close run happen there, never on the host
	// (errata #26, wave 4). nil = host Runtime.Enforcement and no close run (tests).
	Exec     func(ctx context.Context, cmd ...string) ([]byte, error)
	WallUnit time.Duration // unit of max_wall_minutes; 0 = time.Minute (tests shrink it)
	// Start opens the task's journal (flow.Env.Start, Actor autonomy, state outside the
	// checkout); Close is the host-side close (flow.Env.Close with verify.WithSandbox).
	// nil = not wired (tests).
	Start func(ctx context.Context, t Task) error
	Close func(ctx context.Context, id string) error

	eff     core.EffectivePolicy
	inForce []byte // riskrails.yaml read from the default branch at the tip the run started from
	base    string // the commit every task starts from == tip of the default branch at start
	halter  Halter
	cancel  context.CancelFunc
}

// PolicyFileName is the policy in force the runner writes into StateDir (outside
// the checkout) and mounts read-only into the container.
const PolicyFileName = "policy-in-force.yaml"

var taskIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,60}$`)

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (r *Runner) refuse(ctx context.Context, code, detail string) error {
	e := &core.Refusal{Code: code, Detail: detail}
	_ = r.log(ctx, "refused", map[string]any{"code": code, "detail": detail}) // already refusing
	return e
}

func (r *Runner) log(ctx context.Context, typ string, data map[string]any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = r.Journal.Append(ctx, core.Event{Type: typ, Task: r.RunID, Actor: core.ActorAutonomy, Via: "runner", PolicySHA: r.eff.PolicySHA, Data: b})
	if err != nil {
		return fmt.Errorf("journal %s: %w", typ, err)
	}
	return nil
}

func (r *Runner) git(ctx context.Context, args ...string) (string, error) {
	out, err := gitx.Run(ctx, "", append([]string{"-C", r.Root}, args...)...)
	return strings.TrimSpace(string(out)), err
}

// snapshot reads the policy in force from the remote, at the tip of the default
// branch, and resolves it.
func (r *Runner) snapshot(ctx context.Context) (inForceSHA string, err error) {
	tip, err := r.Hosting.BranchSHA(ctx, r.DefaultBranch)
	if err != nil {
		return "", fmt.Errorf("tip of %s unreadable: %w", r.DefaultBranch, err)
	}
	b, err := r.Hosting.ReadFile(ctx, tip, "riskrails.yaml")
	if err != nil {
		return "", fmt.Errorf("policy in force unreadable: %w", err)
	}
	if r.eff, err = r.Resolve(ctx, b); err != nil {
		return "", fmt.Errorf("resolve policy: %w", err)
	}
	if r.eff.Policy.Project.DefaultBranch != r.DefaultBranch {
		return "", fmt.Errorf("default branch %q differs from policy %q", r.DefaultBranch, r.eff.Policy.Project.DefaultBranch)
	}
	r.inForce = b
	return sha(b), nil
}

// checkBase fails closed unless the commit the run started from is still the
// tip of the default branch on the remote. moved = false with a non-nil error is
// an API failure (halt); moved = true means the branch advanced (block the task).
func (r *Runner) checkBase(ctx context.Context) (moved bool, err error) {
	tip, err := r.Hosting.BranchSHA(ctx, r.DefaultBranch)
	if err != nil {
		return false, fmt.Errorf("tip of %s unreadable: %w", r.DefaultBranch, err)
	}
	return tip != r.base, nil
}

// preflight checks everything that must hold before the first wave and returns
// the commit every task branches from.
// enforcement is measured in the image the agent runs in (Exec), not on the host.
// It needs the policy in force file mounted, so it runs after the first snapshot.
func (r *Runner) enforcement(ctx context.Context) (core.Enforcement, error) {
	var enf core.Enforcement
	var err error
	if r.Exec != nil { // measured in the image the agent runs in, not on the host
		out, xerr := r.Exec(ctx, "rr", "run", "enforcement", "--runtime", r.Runtime.Name())
		if xerr != nil {
			return "", fmt.Errorf("enforcement in the image: %w", xerr)
		}
		enf = core.Enforcement(strings.TrimSpace(string(out)))
	} else if enf, err = r.Runtime.Enforcement(ctx, r.Root); err != nil {
		return "", fmt.Errorf("enforcement: %w", err)
	}
	if enf != core.EnforcementSandbox {
		return "", &core.Refusal{Code: "ENFORCEMENT", Detail: string(enf) + " cannot run " + r.Level.String() + "; autonomy is capped at L1"}
	}
	return enf, nil
}

func (r *Runner) preflight(ctx context.Context, queue []Task) (base string, err error) {
	if r.Level < core.L2 {
		return "", fmt.Errorf("rr run is for L2 and above, got %s", r.Level)
	}
	if r.Clock == nil {
		r.Clock = realClock{}
	}
	for _, t := range queue {
		if !taskIDRe.MatchString(t.ID) {
			return "", fmt.Errorf("invalid task id %q", t.ID)
		}
	}
	if err := requireRealGitDir(r.Root); err != nil {
		return "", err
	}
	if inside, werr := within(r.Root, r.StateDir); werr != nil || inside {
		return "", fmt.Errorf("state dir %q must be outside the checkout %q (err: %v)", r.StateDir, r.Root, werr) //nolint:errorlint // werr may be nil
	}
	if st, gerr := r.git(ctx, "status", "--porcelain"); gerr != nil || st != "" {
		return "", fmt.Errorf("checkout must be clean (status: %q, err: %v)", st, gerr) //nolint:errorlint // gerr may be nil
	}
	if base, err = r.git(ctx, "rev-parse", "HEAD"); err != nil {
		return "", err
	}
	tip, err := r.Hosting.BranchSHA(ctx, r.DefaultBranch)
	if err != nil {
		return "", r.refuse(ctx, "BASE_UNKNOWN", err.Error())
	}
	if tip != base {
		return "", r.refuse(ctx, "BASE_NOT_TIP", "HEAD "+base+" is not the tip "+tip+" of "+r.DefaultBranch+" on the remote")
	}
	r.base = base
	return base, nil
}

// Run processes the queue. It returns a *core.Refusal when it stops (HALT,
// BUDGET, CEILING_CHANGED, ENFORCEMENT, JOURNAL_TAMPERED); outcomes so far are returned too.
func (r *Runner) Run(ctx context.Context, queue []Task) ([]Outcome, error) {
	base, err := r.preflight(ctx, queue)
	if err != nil {
		return nil, err
	}
	inForce, err := r.snapshot(ctx)
	if err != nil {
		return nil, &core.Refusal{Code: "POLICY_UNREADABLE", Detail: err.Error()}
	}
	if err := os.WriteFile(filepath.Join(r.StateDir, PolicyFileName), r.inForce, 0o600); err != nil {
		return nil, fmt.Errorf("write policy in force: %w", err)
	}
	enf, err := r.enforcement(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := r.Journal.Append(ctx, core.Event{Type: "task_started", Task: r.RunID, Actor: core.ActorAutonomy, Via: "runner", PolicySHA: r.eff.PolicySHA}); err != nil {
		return nil, fmt.Errorf("journal task_started: %w", err)
	}
	defer func() { _ = r.Journal.Close(ctx, r.RunID) }()
	if err := r.log(ctx, "autonomy_level", map[string]any{"requested": r.Level, "ceiling_sha": r.eff.CeilingSHA,
		"in_force_sha": inForce, "enforcement": enf}); err != nil {
		return nil, err
	}

	agentCtx, cancelAgents := context.WithCancel(ctx)
	defer cancelAgents()
	r.cancel = cancelAgents
	pollCtx, stopPoll := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	every, haltFile := PollEvery(r.eff.Policy), r.eff.Policy.Autonomy.KillSwitch.RemoteFile // copied: r.eff is replaced by gate
	go func() {
		defer wg.Done()
		r.halter.Poll(pollCtx, r.Clock, every, func(c context.Context) error {
			return CheckHalt(c, r.Hosting, r.DefaultBranch, haltFile)
		}, cancelAgents)
	}()
	defer func() { stopPoll(); wg.Wait() }()
	if r.HaltSock != "" {
		stop, err := r.halter.Serve(r.HaltSock)
		if err != nil {
			return nil, err
		}
		defer stop()
	}

	var out []Outcome
	for _, t := range queue {
		if err := r.gate(ctx); err != nil {
			return out, err
		}
		o, err := r.task(ctx, agentCtx, t, base)
		if o.Task != "" {
			out = append(out, o)
		}
		if err != nil {
			return out, err
		}
	}
	if err := r.anchor().verify(); err != nil {
		return out, r.refuse(ctx, "JOURNAL_TAMPERED", err.Error())
	}
	return out, nil
}

func (r *Runner) anchor() anchor { return anchor{r.Root, r.StateDir, r.RunID} }

// requireRealGitDir: a `.git` file (worktree/gitdir pointer) or symlink would stay writable for the agent.
func requireRealGitDir(root string) error {
	fi, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("%s/.git must be a real directory (err: %w)", root, err)
	}
	return nil
}

// within reports whether path (after resolving symlinks) is inside root.
func within(root, path string) (bool, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return false, err
	}
	rr, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, err
	}
	pp, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(rr, pp)
	if err != nil {
		return false, err
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// gate runs before every wave: HALT, ceiling and policy-in-force hashes, journal
// copies, then the daily budget.
func (r *Runner) gate(ctx context.Context) error {
	halt := r.halter.Halted()
	if halt == "" {
		if err := CheckHalt(ctx, r.Hosting, r.DefaultBranch, r.eff.Policy.Autonomy.KillSwitch.RemoteFile); err != nil {
			halt = err.Error()
		}
	}
	if halt != "" {
		return r.halted(ctx, halt)
	}
	start, err := r.startFacts(ctx)
	if err != nil {
		return r.refuse(ctx, "JOURNAL_UNREADABLE", err.Error())
	}
	nowSHA, err := r.snapshot(ctx)
	if err != nil {
		return r.refuse(ctx, "POLICY_UNREADABLE", err.Error())
	}
	for _, c := range []struct{ what, was, now string }{
		{"policy_in_force", start.InForce, nowSHA}, {"ceiling", start.Ceiling, r.eff.CeilingSHA},
	} {
		if c.was != c.now {
			_ = r.log(ctx, "ceiling_changed", map[string]any{"what": c.what, "was": c.was, "now": c.now})
			return &core.Refusal{Code: "CEILING_CHANGED", Detail: c.what + " changed since the run started"}
		}
	}
	if err := r.anchor().verify(); err != nil {
		return r.refuse(ctx, "JOURNAL_TAMPERED", err.Error())
	}
	return nil
}

func (r *Runner) halted(ctx context.Context, reason string) error {
	_ = r.log(ctx, "run_halted", map[string]any{"reason": reason})
	return &core.Refusal{Code: "HALT", Detail: reason}
}

type startFacts struct{ InForce, Ceiling string }

// startFacts reads the trusted hashes back from the runner's journal.
func (r *Runner) startFacts(ctx context.Context) (f startFacts, err error) {
	evs, err := r.Journal.Events(ctx, r.RunID)
	if err != nil {
		return f, err
	}
	for _, e := range evs {
		if e.Type != "autonomy_level" {
			continue
		}
		var d struct {
			Ceiling string `json:"ceiling_sha"`
			InForce string `json:"in_force_sha"`
			Task    string `json:"task"`
		}
		if json.Unmarshal(e.Data, &d) == nil && d.Task == "" && d.InForce != "" {
			return startFacts{d.InForce, d.Ceiling}, nil
		}
	}
	return f, errors.New("no autonomy_level start event in the run journal")
}

// tasksToday increments and returns today's task count (persisted outside the sandbox).
func (r *Runner) tasksToday() (int, error) {
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return 0, err
	}
	p := filepath.Join(r.StateDir, "tasks-"+r.Clock.Now().UTC().Format("2006-01-02"))
	n := 0
	if b, err := os.ReadFile(p); err == nil {
		if n, err = strconv.Atoi(strings.TrimSpace(string(b))); err != nil {
			return 0, err
		}
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	return n + 1, os.WriteFile(p, []byte(strconv.Itoa(n+1)), 0o600)
}

// haltTask keeps the agent's tracked/untracked work for a human, but not the
// L2 manifests or ignored files (node_modules/.bin, .envrc …) (Opus round 3).
func (r *Runner) haltTask(ctx context.Context, reason string, files []core.File, tracked map[string]bool) error {
	if err := r.restore(ctx, files, tracked); err != nil {
		reason += "; restore manifests: " + err.Error()
	}
	_, _ = r.git(ctx, "clean", "-ffdqX", "-e", "/.rr")
	return r.halted(ctx, reason)
}

// discard drops an over-budget task: manifests restored, tree back at base.
func (r *Runner) discard(ctx context.Context, files []core.File, tracked map[string]bool, base string) {
	_ = r.restore(ctx, files, tracked) // reset below overwrites tracked files anyway
	r.reset(ctx, base)
}

func (r *Runner) reset(ctx context.Context, base string) {
	_, _ = r.git(ctx, "checkout", "-f", "-q", base)
	r.clean(ctx)
}

// clean removes untracked AND ignored files (node_modules, vendor, .env the agent
// planted) so the next task, verify and Rescore never see them; only the runner's
// own .rr stays. Dependencies are reinstalled per task: accepted price.
func (r *Runner) clean(ctx context.Context) {
	_, _ = r.git(ctx, "clean", "-ffdqx", "-e", "/.rr")
}

// dailyLimit counts this task against max_tasks_per_day (persisted in the state dir).
func (r *Runner) dailyLimit(ctx context.Context, pol core.Policy) error {
	lim := pol.Autonomy.Unattended.MaxTasksPerDay
	if lim == nil {
		return nil
	}
	n, err := r.tasksToday()
	if err != nil {
		return r.refuse(ctx, "BUDGET_UNREADABLE", err.Error())
	}
	if n > *lim {
		_ = r.log(ctx, "run_budget_exceeded", map[string]any{"what": "tasks_per_day", "limit": *lim, "used": n - 1})
		return &core.Refusal{Code: "BUDGET", Detail: "max_tasks_per_day reached"}
	}
	return nil
}

// task runs one wave. agentCtx is cancelled by a HALT.
func (r *Runner) task(ctx, agentCtx context.Context, t Task, base string) (Outcome, error) {
	pol := r.eff.Policy
	if t.Mode == "" {
		t.Mode = core.ModeLight
	}
	if t.Tier == "" {
		t.Tier = core.TierBalanced
	}
	lvl, why := TaskLevel(LevelInput{Policy: pol, Mode: t.Mode, Irreversible: t.Irreversible,
		Enforcement: core.EnforcementSandbox, InContainer: r.Container})
	lvl = min(lvl, r.Level)
	o := Outcome{Task: t.ID, Level: lvl, Status: "skipped"}
	if err := r.log(ctx, "autonomy_level", map[string]any{"task": t.ID, "level": lvl, "reason": why, "skipped": lvl < core.L2}); err != nil {
		return o, err
	}
	if lvl < core.L2 {
		return o, nil
	}
	if err := r.dailyLimit(ctx, pol); err != nil {
		return o, err
	}

	if o, stop, err := r.gateTask(ctx, o, t); stop {
		return o, err
	}
	branch := "rr/" + t.ID
	_, _ = r.git(ctx, "branch", "-D", "-q", branch) // a rerun of the same task id; absent is fine
	if _, err := r.git(ctx, "switch", "-q", "-c", branch); err != nil {
		return o, err
	}
	files, err := rrsync.Render(ctx, core.SyncInput{Root: r.Root, Home: r.Home, Policy: r.eff, Tiers: r.Tiers, Level: lvl}, r.Gens)
	if err != nil {
		r.reset(ctx, base)
		return o, r.refuse(ctx, "RENDER", err.Error())
	}
	tracked, err := r.trackedAmong(ctx, files)
	if err != nil {
		r.reset(ctx, base)
		return o, err
	}
	if err := safeWrite(r.Root, files); err != nil {
		r.reset(ctx, base)
		return o, r.refuse(ctx, "RENDER", err.Error())
	}

	waveCtx, endWave := r.waveContext(agentCtx, pol.Autonomy.Unattended.MaxWallMinutes)
	defer endWave()
	rep, werr := r.Worker.Run(waveCtx, core.WorkerSpec{Role: "implementer", Tier: t.Tier, MaxTurns: t.MaxTurns, Worktree: r.Root,
		Brief: "Task id: " + t.ID + "\n\n" + t.Brief, Budget: pol.Models.Budgets[t.Mode]})

	if reason := r.halter.Halted(); reason != "" {
		return o, r.haltTask(ctx, reason, files, tracked)
	}
	if err := ctx.Err(); err != nil { // the caller stopped the run: not a wall-clock budget
		return o, err
	}
	if waveCtx.Err() != nil {
		r.discard(ctx, files, tracked, base)
		_ = r.log(ctx, "run_budget_exceeded", map[string]any{"what": "wall", "limit": pol.Autonomy.Unattended.MaxWallMinutes})
		return o, &core.Refusal{Code: "BUDGET", Detail: "max_wall_minutes reached"}
	}
	head, size, ok, aerr := r.anchor().snapshot(t.ID)
	if aerr != nil {
		r.reset(ctx, base)
		return o, r.refuse(ctx, "JOURNAL_TAMPERED", aerr.Error())
	}
	if err := r.log(ctx, "journal_anchor", map[string]any{"task": t.ID, "head": head, "bytes": size, "missing": !ok}); err != nil {
		return o, err
	}
	// usage unknown (codex prints none; a failed worker may print none) counts as exceeded
	if b := pol.Models.Budgets[t.Mode]; b > 0 && (rep.Tokens <= 0 || rep.Tokens > int64(b)) {
		r.discard(ctx, files, tracked, base)
		_ = r.log(ctx, "run_budget_exceeded", map[string]any{"what": "tokens", "task": t.ID, "limit": b, "used": rep.Tokens})
		return o, &core.Refusal{Code: "BUDGET", Detail: "token budget of " + string(t.Mode) + " exceeded or usage unknown"}
	}
	return r.deliver(ctx, t, o, rep, werr, files, tracked, base)
}

// waveContext applies max_wall_minutes to one wave.
func (r *Runner) waveContext(agentCtx context.Context, minutes *int) (context.Context, context.CancelFunc) {
	if minutes == nil {
		return agentCtx, func() {}
	}
	unit := r.WallUnit
	if unit == 0 {
		unit = time.Minute
	}
	return context.WithTimeout(agentCtx, time.Duration(*minutes)*unit)
}

// gateTask runs before the agent: the base must still be the remote tip, then the
// task journal and scope file. stop = the task does not run (err may be nil: blocked).
func (r *Runner) gateTask(ctx context.Context, o Outcome, t Task) (Outcome, bool, error) {
	moved, err := r.checkBase(ctx)
	if err != nil {
		return o, true, r.halted(ctx, err.Error())
	}
	if moved {
		o.Status = "blocked"
		return o, true, r.log(ctx, "task_blocked", map[string]any{"task": t.ID, "reason": "default branch moved since the run started"})
	}
	if err := r.startTask(ctx, t); err != nil {
		return o, true, r.refuse(ctx, "TASK_START", err.Error())
	}
	return o, false, nil
}

// ScopeFileName is the task's file list the runner writes into StateDir.
const ScopeFileName = "scope.json"

// startTask writes the scope file the container mounts read-only (errata #41),
// then opens the task journal outside the checkout.
func (r *Runner) startTask(ctx context.Context, t Task) error {
	files := t.Files
	if files == nil {
		files = []string{}
	}
	b, err := json.Marshal(files)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.StateDir, ScopeFileName), b, 0o600); err != nil {
		return err
	}
	if r.Start == nil {
		return nil
	}
	return r.Start(ctx, t)
}

// closeRun is the host-side close of the task (adapters run in a fresh sandbox
// container, errata #41); "" = passed or not wired.
func (r *Runner) closeRun(ctx context.Context, id string) string {
	if r.Close == nil {
		return ""
	}
	if err := r.Close(ctx, id); err != nil {
		return "close failed: " + firstLine(err.Error())
	}
	return ""
}

// beforePush re-checks the kill switch and that the default branch has not moved.
func (r *Runner) beforePush(ctx context.Context, killFile string) (moved bool, err error) {
	if err := CheckHalt(ctx, r.Hosting, r.DefaultBranch, killFile); err != nil {
		return false, err
	}
	return r.checkBase(ctx)
}

// deliver turns a finished worker into a draft PR, or blocks the task.
func (r *Runner) deliver(ctx context.Context, t Task, o Outcome, rep core.WorkerReport, werr error, files []core.File, tracked map[string]bool, base string) (Outcome, error) {
	pol, branch := r.eff.Policy, "rr/"+t.ID
	block := func(reason string) (Outcome, error) {
		o.Status = "blocked"
		r.reset(ctx, base)
		return o, r.log(ctx, "task_blocked", map[string]any{"task": t.ID, "status": rep.Status, "reason": reason})
	}
	if werr != nil {
		return block(werr.Error())
	}
	if rep.Status != core.StatusDone && rep.Status != core.StatusDoneWithConcerns {
		return block("worker status " + string(rep.Status))
	}

	if err := r.restore(ctx, files, tracked); err != nil {
		return block("restore manifests: " + err.Error())
	}
	changed, deleted, err := r.stage(ctx)
	if err != nil {
		return block(err.Error())
	}
	if len(changed) == 0 {
		o.Status = "empty"
		r.reset(ctx, base)
		return o, nil
	}
	for _, c := range changed {
		for _, p := range append(append([]string{}, core.AlwaysProtected...), pol.Enforcement.ProtectedPaths...) {
			if globs.Match(p, c) {
				return block("changes protected path " + c)
			}
		}
	}
	if why, err := r.rescore(ctx, t, base, changed, deleted); err != nil || why != "" {
		if err != nil {
			why = "rescore failed: " + err.Error()
		}
		return block(why)
	}
	if why := r.closeRun(ctx, t.ID); why != "" {
		return block(why)
	}
	title := "rr(" + t.ID + "): " + firstLine(t.Brief)
	if _, err := r.git(ctx, "-c", "user.name=rr-runner", "-c", "user.email=rr-runner@localhost", "commit", "-q", "-m", title); err != nil {
		return block(err.Error())
	}
	if moved, err := r.beforePush(ctx, pol.Autonomy.KillSwitch.RemoteFile); err != nil {
		return o, r.halted(ctx, err.Error())
	} else if moved {
		return block("default branch moved before push")
	}
	if err := r.Hosting.Push(ctx, r.Root, branch); err != nil {
		return block("push: " + err.Error())
	}
	labels := []string{"rr", "rr:" + o.Level.String(), "rr:mode:" + string(t.Mode)}
	pr, err := r.Hosting.OpenDraftPR(ctx, branch, r.DefaultBranch, title, prBody(t, o.Level, rep), labels)
	if err != nil {
		return block("open draft PR: " + err.Error())
	}
	o.Status, o.PR = "pr", pr
	if _, err := r.git(ctx, "switch", "-q", "--detach", base); err != nil {
		return o, err
	}
	r.clean(ctx)
	return o, r.log(ctx, "draft_pr_opened", map[string]any{"task": t.ID, "branch": branch, "number": pr.Number, "url": pr.URL})
}

// trackedAmong lists which rendered files are tracked, so they can be restored.
func (r *Runner) trackedAmong(ctx context.Context, files []core.File) (map[string]bool, error) {
	out, err := r.git(ctx, "ls-files")
	if err != nil {
		return nil, err
	}
	in := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		in[l] = true
	}
	tracked := map[string]bool{}
	for _, f := range files {
		tracked[f.Path] = in[f.Path]
	}
	return tracked, nil
}

// restore puts the committed version of every rendered manifest back (tracked)
// or deletes it: the L≥2 manifests live in the container only and are never committed.
func (r *Runner) restore(ctx context.Context, files []core.File, tracked map[string]bool) error {
	if err := checkPaths(r.Root, files); err != nil {
		return err
	}
	for _, f := range files {
		if tracked[f.Path] {
			if _, err := r.git(ctx, "checkout", "-q", "HEAD", "--", f.Path); err != nil {
				return err
			}
		} else if err := os.Remove(filepath.Join(r.Root, f.Path)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// checkPaths Lstats every component from root to each file: a symlink or a
// non-directory parent, or a non-regular file, is refused, never followed.
func checkPaths(root string, files []core.File) error {
	for _, f := range files {
		parts := strings.Split(filepath.Clean(f.Path), string(filepath.Separator))
		cur := root
		for i, p := range parts {
			cur = filepath.Join(cur, p)
			fi, err := os.Lstat(cur)
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				return err
			}
			last := i == len(parts)-1
			if fi.Mode()&os.ModeSymlink != 0 || (!last && !fi.IsDir()) || (last && !fi.Mode().IsRegular()) {
				return fmt.Errorf("%s: %s is a symlink or not a plain file/directory", f.Path, cur)
			}
		}
	}
	return nil
}

// safeWrite writes files under root after checkPaths (rrsync.Write follows symlinks).
func safeWrite(root string, files []core.File) error {
	if err := checkPaths(root, files); err != nil {
		return err
	}
	for _, f := range files {
		dst := filepath.Join(root, f.Path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(f.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(dst, f.Content, mode); err != nil { //nolint:gosec // dst checked by checkPaths
			return err
		}
	}
	return nil
}

// stage stages everything and lists the staged paths. --no-renames lists both
// sides of a move, so a protected source path cannot hide behind a rename.
func (r *Runner) stage(ctx context.Context) (changed []string, deleted map[string]bool, err error) {
	if _, err := r.git(ctx, "add", "-A"); err != nil {
		return nil, nil, err
	}
	out, err := gitx.Run(ctx, "", "-C", r.Root, "diff", "--cached", "--raw", "--no-renames", "-z")
	if err != nil {
		return nil, nil, err
	}
	deleted = map[string]bool{}
	if len(out) == 0 {
		return nil, deleted, nil
	}
	f := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(f)%2 != 0 {
		return nil, nil, fmt.Errorf("unparsable diff --raw output")
	}
	for i := 0; i+1 < len(f); i += 2 {
		// ":<oldmode> <newmode> <oldsha> <newsha> <status>"
		m := strings.Fields(strings.TrimPrefix(f[i], ":"))
		if len(m) != 5 {
			return nil, nil, fmt.Errorf("unparsable diff --raw entry %q", f[i])
		}
		if m[1] == "120000" || m[1] == "160000" || strings.HasPrefix(m[4], "T") {
			return nil, nil, fmt.Errorf("symlink/gitlink in diff: %s", f[i+1])
		}
		changed = append(changed, f[i+1])
		if strings.HasPrefix(m[4], "D") {
			deleted[f[i+1]] = true
		}
	}
	return changed, deleted, nil
}

// rescore re-measures the real diff (triage.Rescore). A higher mode or an
// irreversible change means the level no longer covers the task.
func (r *Runner) rescore(ctx context.Context, t Task, base string, changed []string, deleted map[string]bool) (string, error) {
	pol := r.eff.Policy
	tree, err := r.treeAt(ctx, base)
	if err != nil {
		return "", err
	}
	var live []string
	for _, c := range changed {
		if !deleted[c] {
			live = append(live, c)
		}
	}
	refs, content, unreadable := triage.Load(r.Root, live, tree, pol.Risk.Axes[core.AxisCoverage].TestGlobs)
	prev := core.Weight{Axes: map[core.Axis]int{}, Mode: t.Mode, Irreversible: t.Irreversible}
	w := triage.Rescore(pol, prev, triage.Input{Files: changed, Goal: t.Brief, Refs: refs, Tree: tree,
		Content: content, Unreadable: unreadable, Deleted: deleted})
	if w.Mode.Rank() > t.Mode.Rank() || (w.Irreversible && !t.Irreversible) {
		return fmt.Sprintf("rescored to %s (irreversible=%v) from declared %s", w.Mode, w.Irreversible, t.Mode), nil
	}
	return "", nil
}

// treeAt lists the files of a commit, NUL-separated so unusual names stay intact.
func (r *Runner) treeAt(ctx context.Context, rev string) ([]string, error) {
	out, err := gitx.Run(ctx, "", "-C", r.Root, "ls-tree", "-r", "-z", "--name-only", rev)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, n := range strings.Split(string(out), "\x00") {
		if n != "" {
			names = append(names, n)
		}
	}
	return names, nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(l) > 72 {
		l = strings.ToValidUTF8(l[:72], "")
	}
	return l
}

func prBody(t Task, lvl core.Level, rep core.WorkerReport) string {
	body := rep.Body
	if len(body) > 4000 {
		body = strings.ToValidUTF8(body[:4000], "") + "\n…"
	}
	body = strings.ReplaceAll(body, "@", "@\u200b") // no mentions, also outside the fence
	fence, run := "```", 0
	for _, c := range body + "\x00" { // longest backtick run
		if c == '`' {
			run++
			continue
		}
		if run >= len(fence) {
			fence = strings.Repeat("`", run+1)
		}
		run = 0
	}
	return fmt.Sprintf("## rr task %s\n\n- level: %s (label `rr:%s`)\n- mode: %s\n- weight: declared only, irreversible=%v\n"+
		"- worker: %s, %d calls\n- cost: %d tokens (worker status, calls and cost are reported by the agent: advisory)\n- review verdict: none yet; required human review on the server\n\n"+
		"### Worker report (agent text, untrusted)\n\n%s\n%s\n%s\n", t.ID, lvl, lvl, t.Mode, t.Irreversible, rep.Status, rep.Calls, rep.Tokens, fence, body, fence)
}
