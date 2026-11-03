package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vanssata/agentic-risk-rails/internal/factory"
)

// The factory names the scope variable itself to avoid an import cycle.
func TestFactoryEnvScopeIsTheHookVariable(t *testing.T) {
	assert.Equal(t, EnvScope, factory.EnvScope)
}
