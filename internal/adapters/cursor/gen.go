package cursor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// hookTimeout (seconds) is above rr guard's own 2 s deadline.
const hookTimeout = 10

type hooksFile struct {
	Version int                      `json:"version"`
	Hooks   map[string][]hookHandler `json:"hooks"`
}

type hookHandler struct {
	Command    string `json:"command"`
	Type       string `json:"type"`
	Timeout    int    `json:"timeout"`
	FailClosed bool   `json:"failClosed"`
	Matcher    string `json:"matcher,omitempty"`
}

type hooksGen struct{}

func (hooksGen) Name() string { return "cursor-hooks" }

// Render emits .cursor/hooks.json. Ask is always a deny in the adapter, so the
// output does not depend on in.Level.
func (hooksGen) Render(context.Context, core.SyncInput) ([]core.File, error) {
	f := hooksFile{Version: 1, Hooks: map[string][]hookHandler{}}
	for _, e := range events {
		h := hookHandler{
			Command: "rr guard --runtime cursor --event " + e + " || exit 2",
			Type:    "command", Timeout: hookTimeout, FailClosed: true,
		}
		if e == "preToolUse" {
			h.Matcher = "*"
		}
		f.Hooks[e] = []hookHandler{h}
	}
	b, err := json.MarshalIndent(f, "", "  ") // map keys are sorted: deterministic
	if err != nil {
		return nil, fmt.Errorf("cursor hooks: %w", err)
	}
	return []core.File{{Path: ".cursor/hooks.json", Content: append(b, '\n')}}, nil
}
