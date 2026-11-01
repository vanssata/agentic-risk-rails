package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/gitx"
	"github.com/vanssata/agentic-risk-rails/internal/globs"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
	"github.com/vanssata/agentic-risk-rails/internal/projection"
	"github.com/vanssata/agentic-risk-rails/internal/verify"
)

// oneLine collapses whitespace and control characters (journal text must not
// inject markdown structure) and cuts to n runes.
func oneLine(s string, n int) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// gates are the events a successor session needs to read before anything else.
var gates = map[string]bool{"plan_accepted": true, "review_verdict": true, "refused": true, "scope_violation": true,
	"weight_amended": true, "weight_rescored": true, "review_budget": true, "wave_blocked": true, "risk_recorded": true, "risk_resolved": true}

// Handoff writes .rr/run/<task>/handoff.md (DES §16.3 rule 4): a projection of
// the journal plus the current diff, no state of its own. It returns the path.
func (e Env) Handoff(ctx context.Context, task string) (string, error) {
	events, err := e.Journal.Events(ctx, task)
	if err != nil {
		return "", err
	}
	d, err := readStarted(events)
	if err != nil {
		return "", err
	}
	tr, err := verify.LoadTrust(e.Root, task, events)
	if err != nil {
		return "", err
	}
	mode, err := verify.TaskMode(events)
	if err != nil {
		return "", err
	}
	changed, err := verify.TaskChanged(ctx, e.Root, tr, true)
	if err != nil {
		return "", err
	}
	stat, err := gitx.Run(ctx, "", "-C", e.Root, "diff", "--stat", "--no-renames", "--end-of-options", tr.BaseSHA, "--")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Handoff %s\n\nRead this before anything else. It is a projection of the journal and the current diff.\n\n", task)
	fmt.Fprintf(&b, "- goal: %s\n- mode: %s\n- scope: %s\n- events: %d\n\n", oneLine(d.Goal, 300), mode, oneLine(strings.Join(d.Scope, ", "), 300), len(events))
	b.WriteString("## Decisions and gates\n\n")
	for _, ev := range events {
		if gates[ev.Type] {
			fmt.Fprintf(&b, "- %s %s by %s: %s\n", ev.Time.UTC().Format("15:04:05"), ev.Type, ev.Actor, oneLine(string(ev.Data), 300))
		}
	}
	b.WriteString("\n## Open risks\n\n")
	for _, r := range projection.Risks(events) {
		fmt.Fprintf(&b, "- %s\n", oneLine(string(r.Data), 300))
	}
	b.WriteString("\n## Changed since the task started\n\n")
	for _, c := range changed {
		fmt.Fprintf(&b, "- %s\n", oneLine(c, 200))
	}
	fmt.Fprintf(&b, "\n```\n%s```\n\n## Last event\n\n- %s\n", stat, oneLine(lastEvent(events), 300))
	dir := filepath.Join(journal.RunDir(e.Root), task)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "handoff.md")
	return p, os.WriteFile(p, []byte(b.String()), 0o644)
}

func lastEvent(events []core.Event) string {
	e := events[len(events)-1]
	return e.Type + " " + string(e.Data)
}

// Recall answers "what happened to these files before": the tasks (closed and
// open) whose scope covers them with their facts and review verdicts, the open
// risks, and `git log -S` hits for each file's name. The answer is cut to about
// budget tokens (4 bytes each).
func (e Env) Recall(ctx context.Context, files []string, budget int) (string, error) {
	var paths []string
	for _, dir := range []string{journal.TasksDir(e.Root), journal.RunDir(e.Root)} {
		m, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	var lines, risks []string
	for _, p := range paths {
		events, err := journal.ReadFile(p)
		if err != nil {
			return "", err
		}
		for _, r := range projection.Risks(events) {
			risks = append(risks, fmt.Sprintf("- %s: %s", strings.TrimSuffix(filepath.Base(p), ".jsonl"), oneLine(string(r.Data), 200)))
		}
		d, err := readStarted(events)
		if err != nil || !touches(d.Scope, files) {
			continue
		}
		state := "closed"
		if filepath.Base(filepath.Dir(p)) == "run" {
			state = "open"
		}
		lines = append(lines, fmt.Sprintf("- %s [%s] %s", strings.TrimSuffix(filepath.Base(p), ".jsonl"), state, oneLine(d.Goal, 150)))
		for _, ev := range events {
			switch ev.Type {
			case "task_closed", "review_verdict", "scope_violation", "review_budget":
				lines = append(lines, fmt.Sprintf("    %s %s", ev.Type, oneLine(string(ev.Data), 250)))
			}
		}
	}
	var b strings.Builder
	b.WriteString("## Tasks that touched these files\n\n" + strings.Join(lines, "\n") + "\n\n## Open risks\n\n" + strings.Join(risks, "\n") + "\n\n## git log -S\n\n")
	for _, f := range files {
		ident := strings.SplitN(path.Base(filepath.ToSlash(f)), ".", 2)[0]
		if ident == "" {
			continue
		}
		out, err := gitx.Run(ctx, "", "-C", e.Root, "log", "--oneline", "-n", "3", "-S"+ident, "--")
		if err != nil {
			return "", err
		}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if l != "" {
				fmt.Fprintf(&b, "- %s: %s\n", ident, oneLine(l, 150))
			}
		}
	}
	out := b.String()
	if max := budget * 4; len(out) > max {
		out = out[:max] + "\n(truncated to the token budget)\n"
	}
	return out, nil
}

// touches reports whether any scope entry covers any of files.
func touches(scope, files []string) bool {
	for _, s := range scope {
		for _, f := range files {
			if globs.Match(s, filepath.ToSlash(filepath.Clean(f))) {
				return true
			}
		}
	}
	return false
}

var _ = json.Marshal
