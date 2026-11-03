package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/factory"
	"github.com/vanssata/agentic-risk-rails/internal/flow"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/ledger"
	"github.com/vanssata/agentic-risk-rails/internal/models"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// flowEnv resolves the policy of root and builds the flow environment. A resolve
// error refuses: there is no fallback policy for a task.
func flowEnv(ctx context.Context, root string) (flow.Env, resolved, error) {
	r, err := resolve(ctx, root)
	if err != nil {
		return flow.Env{}, r, fmt.Errorf("refusing: policy not resolved: %w", err)
	}
	return flow.Env{Root: r.root, Policy: r.eff, Tree: r.files, Journal: journal.New(r.root), Home: r.home}, r, nil
}

// notAgent refuses the human gates (close, accept, review) when the process looks like
// an agent's shell: CLAUDECODE is set by Claude Code in the Bash tool [U], RR_LEVEL by
// the runner's container. This is a second layer: the boundary is core.AlwaysDeniedCommands
// ("rr task*" is denied to the agent by the guard) plus the sandbox.
func notAgent() error {
	for _, k := range []string{"CLAUDECODE", flow.EnvLevel, factory.EnvWorker} {
		if os.Getenv(k) != "" {
			return fmt.Errorf("refusing: %s is set; close, accept and review are host-side steps after the agent has stopped", k)
		}
	}
	return nil
}

func parseDeclared(declare []string) (map[core.Axis]int, error) {
	out := map[core.Axis]int{}
	for _, d := range declare {
		k, v, ok := strings.Cut(d, "=")
		n, nerr := strconv.Atoi(v)
		var a core.Axis
		if !ok || nerr != nil || n < 0 || n > 2 || a.UnmarshalText([]byte(k)) != nil {
			return nil, fmt.Errorf("--declare %q: want axis=0..2", d)
		}
		out[core.Axis(k)] = n
	}
	return out, nil
}

// taskFlags are the flags shared by the `rr task` subcommands.
type taskFlags struct {
	root, task, goal, runtime, verdict, transcript, severity, plan string
	files, declare                                                 []string
	spec, amend                                                    bool
	sessions                                                       int
	ses                                                            ledger.SessionData
}

// open resolves the policy and the task the subcommand acts on.
func (f *taskFlags) open(cmd *cobra.Command) (flow.Env, string, error) {
	e, _, t, err := f.openR(cmd)
	return e, t, err
}

func (f *taskFlags) openR(cmd *cobra.Command) (flow.Env, resolved, string, error) {
	e, r, err := flowEnv(cmd.Context(), f.root)
	if err != nil {
		return e, r, "", err
	}
	t := f.task
	if t == "" {
		t, err = flow.OpenTask(cmd.Context(), e.Journal)
	}
	return e, r, t, err
}

func printWeight(cmd *cobra.Command, w core.Weight, task string, level *core.Level) {
	out := cmd.OutOrStdout()
	for _, why := range w.Reasons {
		fmt.Fprintln(out, why)
	}
	fmt.Fprintf(out, "task %s\nW %d -> %s", task, w.Total(), w.Mode)
	if level != nil {
		fmt.Fprintf(out, ", level %s", *level)
	}
	fmt.Fprintln(out)
}

func (f *taskFlags) doAmend(cmd *cobra.Command) error {
	declared, err := parseDeclared(f.declare)
	if err != nil {
		return err
	}
	e, t, err := f.open(cmd)
	if err != nil {
		return err
	}
	w, err := e.Amend(cmd.Context(), t, declared, core.ActorHuman)
	if err != nil {
		return err
	}
	printWeight(cmd, w, t, nil)
	return nil
}

func (f *taskFlags) doStart(cmd *cobra.Command) error {
	if f.amend {
		return f.doAmend(cmd)
	}
	declared, err := parseDeclared(f.declare)
	if err != nil {
		return err
	}
	e, r, err := flowEnv(cmd.Context(), f.root)
	if err != nil {
		return err
	}
	tiers, err := models.FromLock(r.eff.Policy.Models, r.root, f.runtime)
	if err != nil {
		return err
	}
	s, err := e.Start(cmd.Context(), flow.StartIn{Goal: f.goal, Files: f.files, Declared: declared, Spec: f.spec, Sessions: f.sessions, Tiers: tiers, Actor: core.ActorHuman})
	if err != nil {
		return err
	}
	printWeight(cmd, s.Weight, s.Task, &s.Level)
	return nil
}

// note records a human gate; like close it is refused in an agent's shell.
func (f *taskFlags) note(cmd *cobra.Command, typ string, data map[string]any) error {
	if err := notAgent(); err != nil {
		return err
	}
	e, t, err := f.open(cmd)
	if err != nil {
		return err
	}
	return e.Note(cmd.Context(), t, typ, core.ActorHuman, data)
}

// doAccept is the human plan gate. Guarded and heavier tasks need a written plan
// file (--plan); only a light task may be accepted without one.
func (f *taskFlags) doAccept(cmd *cobra.Command) error {
	if err := notAgent(); err != nil {
		return err
	}
	e, t, err := f.open(cmd)
	if err != nil {
		return err
	}
	if f.plan != "" {
		if err := e.Accept(cmd.Context(), t, f.plan, core.ActorHuman); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "plan accepted for task %s\n", t)
		return nil
	}
	events, err := e.Journal.Events(cmd.Context(), t)
	if err != nil {
		return err
	}
	mode, err := verify.TaskMode(events)
	if err != nil {
		return err
	}
	if mode != core.ModeLight {
		return fmt.Errorf("refusing: a %s task needs a written plan: rr task accept --plan <file>", mode)
	}
	return e.Note(cmd.Context(), t, "plan_accepted", core.ActorHuman, map[string]any{"plan": "written"})
}

func (f *taskFlags) doResearch(cmd *cobra.Command) error {
	if err := notAgent(); err != nil {
		return err
	}
	e, r, t, err := f.openR(cmd)
	if err != nil {
		return err
	}
	_, ro, _, err := workers(r, f.runtime)
	if err != nil {
		return err
	}
	res, err := e.Research(cmd.Context(), t, ro.ReadOnly(), f.runtime)
	if err != nil {
		return err
	}
	if res.Brief == "" {
		fmt.Fprintf(cmd.OutOrStdout(), "task %s: no research for this mode\n", t)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "task %s: %d scouts (%d cached), brief %s (~%d tokens)\n", t, len(res.Roles), res.CacheHits, res.Brief, res.BriefToken)
	return nil
}

func (f *taskFlags) doBuild(cmd *cobra.Command) error {
	if err := notAgent(); err != nil {
		return err
	}
	e, r, t, err := f.openR(cmd)
	if err != nil {
		return err
	}
	impl, ro, et, err := workers(r, f.runtime)
	if err != nil {
		return err
	}
	res, err := e.Build(cmd.Context(), t, flow.BuildIn{Impl: impl, Reviewer: ro, Runtime: f.runtime, Tiers: et.Models, Actor: core.ActorHuman})
	for _, s := range res {
		fmt.Fprintf(cmd.OutOrStdout(), "step %s: %s\n", s.Step, strings.TrimSpace(s.Commit+" "+s.Blocked))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "task %s: factory PASS\n", t)
	return nil
}

func (f *taskFlags) doClose(cmd *cobra.Command) error {
	if err := notAgent(); err != nil {
		return err
	}
	e, t, err := f.open(cmd)
	if err != nil {
		return err
	}
	in := flow.CloseIn{Task: t, Actor: core.ActorHuman}
	if f.transcript != "" {
		f.ses.Path = f.transcript
		in.Session = &f.ses
	}
	if err := e.Close(cmd.Context(), in); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "task %s closed\n", t)
	return nil
}

func init() {
	cli.Register(func() *cobra.Command {
		wd, _ := os.Getwd()
		var f taskFlags
		c := &cobra.Command{Use: "task", Short: "Task flow: start, research, accept, build, review, close"}
		c.PersistentFlags().StringVar(&f.root, "root", wd, "repository root")
		c.PersistentFlags().StringVar(&f.task, "task", "", "task id (default: the task in flight)")

		start := &cobra.Command{
			Use:   "start",
			Short: "Open a task: triage, baseline, journal (--amend re-measures all six axes of the open task)",
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, _ []string) error { return f.doStart(cmd) },
		}
		start.Flags().StringVar(&f.goal, "goal", "", "task goal (scanned for behaviour keywords)")
		start.Flags().StringSliceVar(&f.files, "files", nil, "repo-relative files or globs the task may touch (its scope)")
		start.Flags().StringSliceVar(&f.declare, "declare", nil, "raise an axis: axis=0..2 (never lowers a measurement)")
		start.Flags().BoolVar(&f.spec, "spec", false, "a spec drives the task (programme trigger)")
		start.Flags().IntVar(&f.sessions, "sessions", 1, "sessions the task spans (programme trigger)")
		start.Flags().StringVar(&f.runtime, "runtime", "claude", "runtime whose locked tiers the task records")
		start.Flags().BoolVar(&f.amend, "amend", false, "re-measure all six axes of the open task instead of starting one")

		amend := &cobra.Command{
			Use: "amend", Short: "Re-measure all six axes against the real diff; the mode only grows", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return f.doAmend(cmd) },
		}
		amend.Flags().StringSliceVar(&f.declare, "declare", nil, "raise an axis: axis=0..2")

		accept := &cobra.Command{
			Use: "accept", Short: "Accept the written plan (--plan; required above light): plan.Check, inside the scope, hash, plan_accepted", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return f.doAccept(cmd) },
		}
		accept.Flags().StringVar(&f.plan, "plan", "", "plan file (DES §6 steps with files); copied into the task's state")
		research := &cobra.Command{
			Use: "research", Short: "Run the read-only scouts of the task's mode and write the merge brief into the task's state", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return f.doResearch(cmd) },
		}
		research.Flags().StringVar(&f.runtime, "runtime", "claude", "worker runtime: claude | codex (must be in project.runtimes)")
		build := &cobra.Command{
			Use: "build", Short: "Run the factory over the accepted plan: workers per step, two-stage review, review_verdict factory", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error { return f.doBuild(cmd) },
		}
		build.Flags().StringVar(&f.runtime, "runtime", "claude", "worker runtime: claude | codex (must be in project.runtimes)")
		review := &cobra.Command{
			Use: "review", Short: "Record the human's review verdict (review_verdict)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if f.verdict != "PASS" && f.verdict != "FAIL" {
					return errors.New("--verdict must be PASS or FAIL")
				}
				return f.note(cmd, "review_verdict", map[string]any{"verdict": f.verdict, "stage": "human"})
			},
		}
		review.Flags().StringVar(&f.verdict, "verdict", "", "PASS or FAIL")

		risk := &cobra.Command{
			Use: "risk <text>", Short: "Record a known open risk (risk_recorded)", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return f.note(cmd, "risk_recorded", map[string]any{"id": fmt.Sprintf("r%d", time.Now().UnixNano()), "text": args[0], "severity": f.severity})
			},
		}
		risk.Flags().StringVar(&f.severity, "severity", "medium", "low | medium | high")

		closeCmd := &cobra.Command{
			Use:   "close",
			Short: "Close the task: rescore, host-side full verify, the two facts, cost, archive (run after the agent has stopped)",
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, _ []string) error { return f.doClose(cmd) },
		}
		closeCmd.Flags().StringVar(&f.transcript, "transcript", "", "absolute path of the session transcript (*.jsonl) to attribute to this task")
		closeCmd.Flags().StringVar(&f.ses.Runtime, "session-runtime", "claude", "runtime of --transcript: claude | codex")
		closeCmd.Flags().StringVar(&f.ses.Session, "session", "", "session id of --transcript")
		closeCmd.Flags().StringVar(&f.ses.Phase, "phase", "implement", "phase of --transcript for rr cost")

		c.AddCommand(start, amend, research, accept, build, review, risk, closeCmd)
		return c
	})
}
