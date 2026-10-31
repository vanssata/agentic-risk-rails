package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Collect turns the journal events of one task into attributed usage. Phase
// comes from ledger_session events, tier from the model via the task's
// tiers_effective (unknown models get tier "?"). For Claude transcripts the
// sidechain files in <transcript>/subagents/ are read too. Transcript paths
// must be absolute, clean, *.jsonl and lie under one of roots; a session path
// listed twice counts once, and a Claude message id counts once per task.
func Collect(events []core.Event, roots []string) ([]Item, error) {
	tierOf := map[string]string{}
	for _, e := range events {
		for t, m := range e.TiersEffective {
			tierOf[m] = string(t)
		}
	}
	var items []Item
	seenPath := map[string]bool{}
	byID := map[string]int{}
	add := func(id string, u core.Usage, phase string) {
		tier, ok := tierOf[u.Model]
		if !ok {
			tier = "?"
		}
		it := Item{Usage: u, Phase: phase, Tier: tier}
		if id != "" {
			if i, ok := byID[id]; ok {
				items[i] = it
				return
			}
			byID[id] = len(items)
		}
		items = append(items, it)
	}
	for _, e := range events {
		if e.Type != EventSession {
			continue
		}
		var d SessionData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return nil, fmt.Errorf("ledger_session data: %w", err)
		}
		if d.Runtime != "claude" && d.Runtime != "codex" {
			return nil, fmt.Errorf("ledger_session: unknown runtime %q", d.Runtime)
		}
		if err := checkPath(d.Path, roots); err != nil {
			return nil, err
		}
		if seenPath[d.Path] {
			continue
		}
		seenPath[d.Path] = true
		files := []string{d.Path}
		if d.Runtime == "claude" {
			sub, _ := filepath.Glob(filepath.Join(strings.TrimSuffix(d.Path, ".jsonl"), "subagents", "*.jsonl"))
			files = append(files, sub...)
		}
		for _, f := range files {
			if err := parseFile(d.Runtime, f, func(id string, u core.Usage) { add(id, u, d.Phase) }); err != nil {
				return nil, err
			}
		}
	}
	return items, nil
}

// checkPath refuses transcript paths that are not absolute, clean .jsonl
// files under one of roots. The error names the path, never file content.
func checkPath(p string, roots []string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || !strings.HasSuffix(p, ".jsonl") {
		return fmt.Errorf("ledger_session: refused transcript path %q", p)
	}
	for _, r := range roots {
		if rel, err := filepath.Rel(r, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("ledger_session: transcript path %q is outside the known transcript roots", p)
}

func parseFile(runtime, path string, emit func(id string, u core.Usage)) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("transcript: %w", err)
	}
	defer f.Close()
	if runtime == "claude" {
		msgs, err := claudeParser{}.parseMsgs(f)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		for _, m := range msgs {
			emit(m.id, m.Usage)
		}
		return nil
	}
	us, err := codexParser{}.Parse(f)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	for _, u := range us {
		emit("", u)
	}
	return nil
}

// TranscriptRoots lists where transcripts may live: Claude and Codex
// directories under home, and the repository's .rr directory.
func TranscriptRoots(home, repoRoot string) []string {
	roots := []string{filepath.Join(home, ".codex", "sessions"), filepath.Join(repoRoot, ".rr")}
	cl, _ := filepath.Glob(filepath.Join(home, ".claude*", "projects"))
	return append(roots, cl...)
}
