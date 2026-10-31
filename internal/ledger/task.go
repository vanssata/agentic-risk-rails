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
// sidechain files in <transcript>/subagents/ are read too.
func Collect(events []core.Event) ([]Item, error) {
	tierOf := map[string]string{}
	for _, e := range events {
		for t, m := range e.TiersEffective {
			tierOf[m] = string(t)
		}
	}
	parsers := Parsers()
	var items []Item
	for _, e := range events {
		if e.Type != EventSession {
			continue
		}
		var d SessionData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return nil, fmt.Errorf("ledger_session data: %w", err)
		}
		p, ok := parsers[d.Runtime]
		if !ok {
			return nil, fmt.Errorf("ledger_session: unknown runtime %q", d.Runtime)
		}
		files := []string{d.Path}
		if d.Runtime == "claude" {
			sub, _ := filepath.Glob(filepath.Join(strings.TrimSuffix(d.Path, ".jsonl"), "subagents", "*.jsonl"))
			files = append(files, sub...)
		}
		for _, f := range files {
			us, err := parseFile(p, f)
			if err != nil {
				return nil, err
			}
			for _, u := range us {
				tier, ok := tierOf[u.Model]
				if !ok {
					tier = "?"
				}
				items = append(items, Item{Usage: u, Phase: d.Phase, Tier: tier})
			}
		}
	}
	return items, nil
}

func parseFile(p core.TranscriptParser, path string) ([]core.Usage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("transcript: %w", err)
	}
	defer f.Close()
	us, err := p.Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return us, nil
}
