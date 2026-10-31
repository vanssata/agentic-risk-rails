// Package projection holds pure functions over journal events: status, risks
// and the closed-task summary. Nothing here touches the filesystem.
package projection

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Summary is the deterministic digest of one task's events.
type Summary struct {
	Task   string          `json:"task"`
	Mode   string          `json:"mode,omitempty"`
	First  time.Time       `json:"first"`
	Last   time.Time       `json:"last"`
	Total  int             `json:"events"`
	Counts map[string]int  `json:"counts"`
	Head   string          `json:"head,omitempty"`   // sha256 of the last line, set at close
	Closed json.RawMessage `json:"closed,omitempty"` // data of task_closed, if present
}

// Summarize digests events (all of one task, in order).
func Summarize(events []core.Event) Summary {
	s := Summary{Counts: map[string]int{}, Total: len(events)}
	for i, e := range events {
		if i == 0 {
			s.Task, s.First = e.Task, e.Time
		}
		s.Last = e.Time
		s.Counts[e.Type]++
		switch e.Type {
		case "task_started":
			var d struct {
				Mode string `json:"mode"`
			}
			if json.Unmarshal(e.Data, &d) == nil && d.Mode != "" {
				s.Mode = d.Mode
			}
		case "task_closed":
			s.Closed = e.Data
		}
	}
	return s
}

// Status is the projection shown by `rr status`.
type Status struct {
	Summary
	Recent []core.Event `json:"recent"`
}

// BuildStatus summarizes events and keeps the last n of them.
func BuildStatus(events []core.Event, n int) Status {
	st := Status{Summary: Summarize(events)}
	if n > len(events) {
		n = len(events)
	}
	if n > 0 {
		st.Recent = events[len(events)-n:]
	}
	return st
}

// Risks returns risk_recorded events not closed by a risk_resolved with the same data.id.
func Risks(events []core.Event) []core.Event {
	id := func(e core.Event) string {
		var d struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(e.Data, &d)
		return d.ID
	}
	resolved := map[string]bool{}
	for _, e := range events {
		if e.Type == "risk_resolved" {
			resolved[id(e)] = true
		}
	}
	var out []core.Event
	for _, e := range events {
		if e.Type == "risk_recorded" && (id(e) == "" || !resolved[id(e)]) {
			out = append(out, e)
		}
	}
	return out
}

// TaskMD renders the minimal deterministic task.md of a closed task.
func TaskMD(s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Task %s\n\n", s.Task)
	fmt.Fprintf(&b, "- mode: %s\n", s.Mode)
	fmt.Fprintf(&b, "- first event: %s\n", s.First.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "- last event: %s\n", s.Last.UTC().Format(time.RFC3339Nano))
	if s.Head != "" {
		fmt.Fprintf(&b, "- head: %s\n", s.Head)
	}
	fmt.Fprintf(&b, "- events: %d\n\n## Events by type\n\n", s.Total)
	types := make([]string, 0, len(s.Counts))
	for t := range s.Counts {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Fprintf(&b, "- %s: %d\n", t, s.Counts[t])
	}
	if len(s.Closed) > 0 {
		fmt.Fprintf(&b, "\n## Closing facts\n\n```json\n%s\n```\n", s.Closed)
	}
	return b.String()
}
