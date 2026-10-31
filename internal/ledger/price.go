package ledger

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

//go:embed prices.json
var pricesJSON []byte

// Price is USD per million tokens.
type Price struct {
	Input      float64 `json:"input"`
	CacheWrite float64 `json:"cache_write"`
	CacheRead  float64 `json:"cache_read"`
	Output     float64 `json:"output"`
}

// Prices maps a model id to its list price.
type Prices map[string]Price

// DefaultPrices loads the embedded table.
func DefaultPrices() (Prices, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(pricesJSON, &raw); err != nil {
		return nil, fmt.Errorf("prices.json: %w", err)
	}
	p := Prices{}
	for k, v := range raw {
		if k == "_doc" {
			continue
		}
		var pr Price
		if err := json.Unmarshal(v, &pr); err != nil {
			return nil, fmt.Errorf("prices.json %s: %w", k, err)
		}
		p[k] = pr
	}
	return p, nil
}

// Cost is the list price of u; ok is false for a model not in the table.
func (p Prices) Cost(u core.Usage) (usd float64, ok bool) {
	pr, ok := p[u.Model]
	if !ok {
		return 0, false
	}
	return (float64(u.Input)*pr.Input + float64(u.CacheWrite)*pr.CacheWrite +
		float64(u.CacheRead)*pr.CacheRead + float64(u.Output)*pr.Output) / 1e6, true
}
