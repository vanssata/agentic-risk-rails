package github

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every operation asks for the token again, so an expired App token is replaced
// mid-run; a token error fails the operation instead of using a stale client.
func TestRefreshingTakesTheTokenPerOperation(t *testing.T) {
	calls := 0
	r := Refreshing{Remote: "acme/shop", token: func(context.Context, string, string) (string, error) {
		calls++
		if calls > 2 {
			return "", errors.New("mint failed")
		}
		return "tok", nil
	}}
	for range 2 {
		c, err := r.client(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "tok", c.token)
	}
	_, err := r.BranchSHA(t.Context(), "main")
	assert.ErrorContains(t, err, "mint failed")
	assert.Equal(t, 3, calls)
}
