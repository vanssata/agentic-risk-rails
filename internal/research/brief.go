package research

import (
	"bytes"
	"fmt"
	"text/template"

	researchtpl "github.com/vanssata/agentic-risk-rails/templates/research"
)

// MaxBriefTokens is the DES §5.4 limit for scout and merge briefs.
const MaxBriefTokens = 3000

// EstimateTokens is a conservative estimator: one token per 4 bytes, rounded up.
func EstimateTokens(s string) int { return (len(s) + 3) / 4 }

type briefData struct {
	Goal   string
	Known  []string
	Budget int64
}

// Brief renders the scout brief: goal, already known, tools, boundaries/budget, output schema.
// Known items are dropped from the end until the brief fits MaxBriefTokens.
func Brief(role, goal string, known []string, budget int64) (string, error) {
	if !validRole(role) {
		return "", fmt.Errorf("research: unknown role %q", role)
	}
	t, err := template.ParseFS(researchtpl.FS, WorkerRole(role)+".tmpl")
	if err != nil {
		return "", fmt.Errorf("research: template %s: %w", role, err)
	}
	for {
		var b bytes.Buffer
		if err := t.Execute(&b, briefData{goal, known, budget}); err != nil {
			return "", fmt.Errorf("research: render %s: %w", role, err)
		}
		if EstimateTokens(b.String()) <= MaxBriefTokens {
			return b.String(), nil
		}
		if len(known) == 0 {
			return "", fmt.Errorf("research: %s brief exceeds %d tokens even without known facts", role, MaxBriefTokens)
		}
		known = known[:len(known)-1]
	}
}
