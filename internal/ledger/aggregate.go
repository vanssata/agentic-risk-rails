package ledger

import (
	"sort"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Item is one Usage attributed to a task phase and tier.
type Item struct {
	core.Usage
	Phase string
	Tier  string
}

// Row is a sum over the items sharing Key.
type Row struct {
	Key        string  `json:"key"`
	Input      int64   `json:"input"`
	Output     int64   `json:"output"`
	CacheRead  int64   `json:"cache_read"`
	CacheWrite int64   `json:"cache_write"`
	USD        float64 `json:"usd"`
	Unpriced   int     `json:"unpriced,omitempty"` // items whose model has no price
}

// Group sums items by dim ("phase", "tier" or "model"), sorted by key.
func Group(items []Item, p Prices, dim string) []Row {
	m := map[string]*Row{}
	for _, it := range items {
		k := map[string]string{"phase": it.Phase, "tier": it.Tier, "model": it.Model}[dim]
		r := m[k]
		if r == nil {
			r = &Row{Key: k}
			m[k] = r
		}
		r.Input += it.Input
		r.Output += it.Output
		r.CacheRead += it.CacheRead
		r.CacheWrite += it.CacheWrite
		if c, ok := p.Cost(it.Usage); ok {
			r.USD += c
		} else {
			r.Unpriced++
		}
	}
	rows := make([]Row, 0, len(m))
	for _, r := range m {
		rows = append(rows, *r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows
}
