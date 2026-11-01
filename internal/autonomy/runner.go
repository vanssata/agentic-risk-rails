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
	Push     func(ctx context.Context, root, branch string) error

	eff    core.EffectivePolicy
	halter Halter
	cancel context.CancelFunc
}

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

// snapshot reads the policy in force from the remote and resolves it.
func (r *Runner) snapshot(ctx context.Context) (inForceSHA string, err error) {
	b, err := r.Hosting.ReadFile(ctx, r.DefaultBranch, "riskrails.yaml")
	if err != nil {
		return "", fmt.Errorf("policy in force unreadable: %w", err)
	}
	if r.eff, err = r.Resolve(ctx, b); err != nil {
		return "", fmt.Errorf("resolve policy: %w", err)
	}
	if r.eff.Policy.Project.DefaultBranch != r.DefaultBranch {
		return "", fmt.Errorf("default branch %q differs from policy %q", r.DefaultBranch, r.eff.Policy.Project.DefaultBranch)
	}
	return sha(b), nil
}

// Run processes the queue. It returns a *core.Refusal when it stops (HALT,
// BUDGET, CEILING_CHANGED, ENFORCEMENT, JOURNAL_TAMPERED); outcomes so far are returned too.
func (r *Runner) Run(ctx context.Context, queue []Task) ([]Outcome, error) {
	if r.Level < core.L2 {
		return nil, fmt.Errorf("rr run is for L2 and above, got %s", r.Level)
	}
	if r.Clock == nil {
		r.Clock = realClock{}
	}
	for _, t := range queue {
		if !taskIDRe.MatchString(t.ID) {
			return nil, fmt.Errorf("invalid task id %q", t.ID)
		}
	}
	enf, err := r.Runtime.Enforcement(ctx, r.Root)
	if err != nil {
		return nil, fmt.Errorf("enforcement: %w", err)
	}
	if enf != core.EnforcementSandbox {
		return nil, &core.Refusal{Code: "ENFORCEMENT", Detail: string(enf) + " cannot run " + r.Level.String() + "; autonomy is capped at L1"}
	}
	if st, err := r.git(ctx, "status", "--porcelain"); err != nil || st != "" {
		return nil, fmt.Errorf("checkout must be clean (status: %q, err: %w)", st, err)
	}
	base, err := r.git(ctx, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}

	inForce, err := r.snapshot(ctx)
	if err != nil {
		return nil, &core.Refusal{Code: "POLICY_UNREADABLE", Detail: err.Error()}
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
	return out, nil
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
	if err := (anchor{r.Root, r.StateDir}).verify(); err != nil {
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

func (r *Runner) reset(ctx context.Context, base string) {
	_, _ = r.git(ctx, "checkout", "-f", "-q", base)
	_, _ = r.git(ctx, "clean", "-fdq")
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
	if lim := pol.Autonomy.Unattended.MaxTasksPerDay; lim != nil {
		n, err := r.tasksToday()
		if err != nil {
			return o, r.refuse(ctx, "BUDGET_UNREADABLE", err.Error())
		}
		if n > *lim {
			_ = r.log(ctx, "run_budget_exceeded", map[string]any{"what": "tasks_per_day", "limit": *lim, "used": n - 1})
			return o, &core.Refusal{Code: "BUDGET", Detail: "max_tasks_per_day reached"}
		}
	}

	branch := "rr/" + t.ID
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
	if err := rrsync.Write(r.Root, files); err != nil {
		r.reset(ctx, base)
		return o, err
	}

	waveCtx := agentCtx
	if m := pol.Autonomy.Unattended.MaxWallMinutes; m != nil {
		var c context.CancelFunc
		waveCtx, c = context.WithTimeout(agentCtx, time.Duration(*m)*time.Minute)
		defer c()
	}
	rep, werr := r.Worker.Run(waveCtx, core.WorkerSpec{Role: "implementer", Tier: t.Tier, MaxTurns: t.MaxTurns, Worktree: r.Root,
		Brief: "Task id: " + t.ID + "\n\n" + t.Brief, Budget: pol.Models.Budgets[t.Mode]})

	if reason := r.halter.Halted(); reason != "" { // the tree stays as the agent left it, for a human
		return o, r.halted(ctx, reason)
	}
	if waveCtx.Err() != nil {
		_ = r.log(ctx, "run_budget_exceeded", map[string]any{"what": "wall", "limit": pol.Autonomy.Unattended.MaxWallMinutes})
		return o, &core.Refusal{Code: "BUDGET", Detail: "max_wall_minutes reached"}
	}
	head, size, ok, aerr := (anchor{r.Root, r.StateDir}).snapshot(t.ID)
	if aerr != nil {
		r.reset(ctx, base)
		return o, r.refuse(ctx, "JOURNAL_TAMPERED", aerr.Error())
	}
	if err := r.log(ctx, "journal_anchor", map[string]any{"task": t.ID, "head": head, "bytes": size, "missing": !ok}); err != nil {
		return o, err
	}
	if b := pol.Models.Budgets[t.Mode]; b > 0 && rep.Tokens > int64(b) {
		_ = r.log(ctx, "run_budget_exceeded", map[string]any{"what": "tokens", "task": t.ID, "limit": b, "used": rep.Tokens})
		return o, &core.Refusal{Code: "BUDGET", Detail: "token budget of " + string(t.Mode) + " exceeded"}
	}
	return r.deliver(ctx, t, o, rep, werr, files, tracked, base)
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
	changed, err := r.stage(ctx)
	if err != nil {
		return block(err.Error())
	}
	if len(changed) == 0 {
		o.Status = "empty"
		r.reset(ctx, base)
		return o, nil
	}
	for _, c := range changed {
		for _, p := range pol.Enforcement.ProtectedPaths {
			if globs.Match(p, c) {
				return block("changes protected path " + c)
			}
		}
	}
	title := "rr(" + t.ID + "): " + firstLine(t.Brief)
	if _, err := r.git(ctx, "-c", "user.name=rr-runner", "-c", "user.email=rr-runner@localhost", "commit", "-q", "-m", title); err != nil {
		return block(err.Error())
	}
	push := r.Push
	if push == nil {
		push = gitPush
	}
	if err := push(ctx, r.Root, branch); err != nil {
		return block("push: " + err.Error())
	}
	pr, err := r.Hosting.OpenDraftPR(ctx, branch, r.DefaultBranch, title, prBody(t, o.Level, rep))
	if err != nil {
		return block("open draft PR: " + err.Error())
	}
	o.Status, o.PR = "pr", pr
	if _, err := r.git(ctx, "switch", "-q", "--detach", base); err != nil {
		return o, err
	}
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

func (r *Runner) stage(ctx context.Context) ([]string, error) {
	if _, err := r.git(ctx, "add", "-A"); err != nil {
		return nil, err
	}
	out, err := gitx.Run(ctx, "", "-C", r.Root, "diff", "--cached", "--name-only", "-z")
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

// gitPush pushes only rr/* branches, never a default branch. Credentials are not
// available to the hardened git (CORE_CHANGE_REQUESTS: Hosting.Push).
func gitPush(ctx context.Context, root, branch string) error {
	if !strings.HasPrefix(branch, "rr/") {
		return fmt.Errorf("refusing to push %q", branch)
	}
	_, err := gitx.Run(ctx, "", "-C", root, "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
		"push", "origin", "refs/heads/"+branch+":refs/heads/"+branch)
	return err
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(l) > 72 {
		l = l[:72]
	}
	return l
}

func prBody(t Task, lvl core.Level, rep core.WorkerReport) string {
	body := rep.Body
	if len(body) > 4000 {
		body = body[:4000] + "\n…"
	}
	return fmt.Sprintf("## rr task %s\n\n- level: %s (label `rr:%s`)\n- mode: %s\n- weight: declared only, irreversible=%v\n"+
		"- worker: %s, %d calls\n- cost: %d tokens\n- review verdict: none yet; required human review on the server\n\n### Worker report\n\n%s\n",
		t.ID, lvl, lvl, t.Mode, t.Irreversible, rep.Status, rep.Calls, rep.Tokens, body)
}
