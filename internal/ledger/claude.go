package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// claudeParser reads Claude Code session JSONL (also subagent files).
type claudeParser struct{}

func (claudeParser) Runtime() string { return "claude" }

type claudeLine struct {
	Type      string    `json:"type"`
	SessionID string    `json:"sessionId"`
	Timestamp time.Time `json:"timestamp"`
	Message   struct {
		ID    string `json:"id"`
		Model string `json:"model"`
		Usage struct {
			Input      int64 `json:"input_tokens"`
			Output     int64 `json:"output_tokens"`
			CacheRead  int64 `json:"cache_read_input_tokens"`
			CacheWrite int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

// Parse returns one Usage per API message. Streaming writes the same
// message.id several times; the last record wins.
func (claudeParser) Parse(r io.Reader) ([]core.Usage, error) {
	var out []core.Usage
	byID := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		var l claudeLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("claude transcript line %d: %w", n, err)
		}
		if l.Type != "assistant" || l.Message.Model == "<synthetic>" {
			continue
		}
		u := core.Usage{
			Runtime: "claude", Session: l.SessionID, Model: l.Message.Model,
			Input: l.Message.Usage.Input, Output: l.Message.Usage.Output,
			CacheRead: l.Message.Usage.CacheRead, CacheWrite: l.Message.Usage.CacheWrite,
			Time: l.Timestamp,
		}
		if i, ok := byID[l.Message.ID]; ok && l.Message.ID != "" {
			out[i] = u
			continue
		}
		byID[l.Message.ID] = len(out)
		out = append(out, u)
	}
	return out, sc.Err()
}
