package ledger

import (
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

// claudeMsg is a Usage with the API message id it came from ("" if none).
type claudeMsg struct {
	id string
	core.Usage
}

// parseMsgs returns one entry per record; streaming repeats are NOT merged
// here so that callers can dedupe across files.
func (claudeParser) parseMsgs(r io.Reader) ([]claudeMsg, error) {
	var out []claudeMsg
	err := eachLine(r, func(l *claudeLine) {
		if l.Type != "assistant" || l.Message.Model == "<synthetic>" {
			return
		}
		out = append(out, claudeMsg{l.Message.ID, core.Usage{
			Runtime: "claude", Session: l.SessionID, Model: l.Message.Model,
			Input: l.Message.Usage.Input, Output: l.Message.Usage.Output,
			CacheRead: l.Message.Usage.CacheRead, CacheWrite: l.Message.Usage.CacheWrite,
			Time: l.Timestamp,
		}})
	})
	return out, err
}

// Parse returns one Usage per API message. Streaming writes the same
// message.id several times; the last record wins.
func (p claudeParser) Parse(r io.Reader) ([]core.Usage, error) {
	msgs, err := p.parseMsgs(r)
	if err != nil {
		return nil, err
	}
	var d dedupe
	for _, m := range msgs {
		d.add(m.id, m.Usage)
	}
	return d.out, nil
}

// dedupe keeps one Usage per non-empty id (last wins), in first-seen order.
type dedupe struct {
	out  []core.Usage
	byID map[string]int
}

func (d *dedupe) add(id string, u core.Usage) {
	if id != "" {
		if i, ok := d.byID[id]; ok {
			d.out[i] = u
			return
		}
		if d.byID == nil {
			d.byID = map[string]int{}
		}
		d.byID[id] = len(d.out)
	}
	d.out = append(d.out, u)
}
