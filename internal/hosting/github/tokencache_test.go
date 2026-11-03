package github

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCacheRefreshesBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	c := &tokenCache{m: map[string]cachedToken{}, now: func() time.Time { return now }}
	n := 0
	mint := func() (string, time.Time, error) {
		n++
		return "tok" + string(rune('0'+n)), now.Add(time.Hour), nil
	}
	get := func() string {
		tok, err := c.get("k", mint)
		require.NoError(t, err)
		return tok
	}
	assert.Equal(t, "tok1", get())
	now = now.Add(54 * time.Minute) // 6 min left: still served
	assert.Equal(t, "tok1", get())
	assert.Equal(t, 1, n)
	now = now.Add(2 * time.Minute) // 4 min left: minted again
	assert.Equal(t, "tok2", get())
	now = now.Add(2 * time.Hour) // long expired
	assert.Equal(t, "tok3", get())
}

func TestTokenCacheFailsClosedAndSkipsUnknownExpiry(t *testing.T) {
	now := time.Now()
	c := &tokenCache{m: map[string]cachedToken{}, now: func() time.Time { return now }}
	_, err := c.get("k", func() (string, time.Time, error) { return "", time.Time{}, errors.New("boom") })
	require.Error(t, err)

	n := 0
	for range 2 { // no expiry from GitHub: never cached
		_, err = c.get("k", func() (string, time.Time, error) { n++; return "t", time.Time{}, nil })
		require.NoError(t, err)
	}
	assert.Equal(t, 2, n)

	// a failed refresh does not serve the stale token
	c.m["k"] = cachedToken{"old", now.Add(time.Minute)}
	_, err = c.get("k", func() (string, time.Time, error) { return "", time.Time{}, errors.New("api down") })
	assert.Error(t, err)
}
