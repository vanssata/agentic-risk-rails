package globs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/globs"
)

func TestMatch(t *testing.T) {
	for _, c := range []struct {
		pat, rel string
		want     bool
	}{
		{".env*", ".env", true},
		{".env*", "app/.env.prod", true}, // gitignore depth for slash-less patterns
		{"riskrails.yaml", "sub/riskrails.yaml", true},
		{"src/Payment/**", "src/Payment/Sub/X.php", true},
		{"src/Payment/*.php", "src/Payment/Sub/X.php", false},
		{"src/Payment/*.php", "src/Payment/X.php", true},
		{".github/workflows/**", "a/.github/workflows/x.yml", false}, // anchored when it has "/"
		{"migrations/**", "./migrations/../migrations/1.sql", true},
		{"[", "x", false},
	} {
		assert.Equal(t, c.want, globs.Match(c.pat, c.rel), "%s ~ %s", c.pat, c.rel)
	}
}
