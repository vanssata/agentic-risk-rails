package verify

import (
	"context"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// generic runs a policy adapter that has no built-in implementation (e.g. lint)
// as its plain cmd. The cmd is split on whitespace like every adapter's; exit 0 passes.
type generic struct{ name string }

func (g generic) Name() string     { return g.name }
func (generic) Detect(string) bool { return true }
func (generic) Map(context.Context, string, []string) ([]string, []string, error) {
	return nil, nil, nil
}

// generic returns the generic items of a selection.
func (s Selection) generic() []Item {
	var out []Item
	for _, it := range s.Items {
		if _, ok := it.Adapter.(generic); ok {
			out = append(out, it)
		}
	}
	return out
}

func (generic) Run(ctx context.Context, root string, spec core.VerifyAdapterSpec, _ []string, _ bool) (core.TestResult, error) {
	return runCmd(ctx, root, spec, nil, true)
}
