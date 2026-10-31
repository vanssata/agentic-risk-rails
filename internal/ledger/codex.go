package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// codexParser reads Codex rollout JSONL.
type codexParser struct{}

func (codexParser) Runtime() string { return "codex" }

type codexLine struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Payload   struct {
		ID         string `json:"id"`    // session_meta
		Model      string `json:"model"` // turn_context
		ResponseID string `json:"response_id"`
		Usage      struct {
			Input      int64 `json:"input_tokens"`
			Cached     int64 `json:"cached_input_tokens"`
			CacheWrite int64 `json:"cache_write_input_tokens"`
			Output     int64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"payload"`
}

// Parse returns one Usage per token_usage_record (the per-response delta).
// OpenAI input_tokens include cached and cache-write tokens; they are split
// out so that Input is the uncached remainder. The event_msg/token_count
// lines repeat the same numbers and are ignored.
func (codexParser) Parse(r io.Reader) ([]core.Usage, error) {
	var out []core.Usage
	var session, model string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		var l codexLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("codex transcript line %d: %w", n, err)
		}
		switch l.Type {
		case "session_meta":
			session = l.Payload.ID
		case "turn_context":
			model = l.Payload.Model
		case "token_usage_record":
			if id := l.Payload.ResponseID; id != "" {
				if seen[id] {
					continue
				}
				seen[id] = true
			}
			u := l.Payload.Usage
			out = append(out, core.Usage{
				Runtime: "codex", Session: session, Model: model,
				Input: u.Input - u.Cached - u.CacheWrite, Output: u.Output,
				CacheRead: u.Cached, CacheWrite: u.CacheWrite, Time: l.Timestamp,
			})
		}
	}
	return out, sc.Err()
}

// Parsers returns the parser for each supported runtime.
func Parsers() map[string]core.TranscriptParser {
	return map[string]core.TranscriptParser{"claude": claudeParser{}, "codex": codexParser{}}
}
