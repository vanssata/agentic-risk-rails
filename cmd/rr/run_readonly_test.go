package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Wave 4.2: the container enforces what the runtimes' sandboxes would have.
func TestReadOnlyPatterns(t *testing.T) {
	e := core.EnforcementSpec{ProtectedPaths: []string{"go.mod", ".env*"},
		Sandbox: core.SandboxSpec{Readonly: []string{"$protected_paths", "vendor/**"}, NoWrite: []string{"db/schema.sql"}}}
	assert.Equal(t, []string{"go.mod", ".env*", "vendor/**", "db/schema.sql"}, readOnlyPatterns(e))
}
