package autonomy

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/core/fakes"
)

// fakeClock fires After timers only on Advance; timers is signalled on every After call.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	waits  []fakeWait
	timers chan struct{}
}

type fakeWait struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), timers: make(chan struct{}, 100)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waits = append(c.waits, fakeWait{c.now.Add(d), ch})
	c.timers <- struct{}{}
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	rest := c.waits[:0]
	for _, w := range c.waits {
		if !w.at.After(c.now) {
			w.ch <- c.now
		} else {
			rest = append(rest, w)
		}
	}
	c.waits = rest
}

func TestCheckHalt(t *testing.T) {
	ctx := context.Background()
	h := &fakes.Hosting{Files: map[string][]byte{}}
	assert.NoError(t, CheckHalt(ctx, h, "main", ".rr/HALT"), "absent file = running")
	h.Files["main:.rr/HALT"] = []byte("stop")
	assert.Error(t, CheckHalt(ctx, h, "main", ".rr/HALT"))
	h = &fakes.Hosting{ReadErr: errors.New("502")}
	assert.Error(t, CheckHalt(ctx, h, "main", ".rr/HALT"), "read error = halt")
}

func TestPollEvery(t *testing.T) {
	p := core.StrictDefaults()
	assert.Equal(t, 60*time.Second, PollEvery(p))
	n := 10
	p.Autonomy.KillSwitch.PollSeconds = &n
	assert.Equal(t, 10*time.Second, PollEvery(p))
	n = 600
	assert.Equal(t, MaxPoll, PollEvery(p), "never above 60 s")
	n = 0
	assert.Equal(t, MaxPoll, PollEvery(p))
}

func TestHaltStopsWithin60sOnFakeClock(t *testing.T) {
	clk := newFakeClock()
	host := &fakes.Hosting{Files: map[string][]byte{}}
	var hl Halter
	cancelled := make(chan struct{})
	done := make(chan struct{})
	go func() {
		hl.Poll(context.Background(), clk, MaxPoll, func(ctx context.Context) error {
			return CheckHalt(ctx, host, "main", ".rr/HALT")
		}, func() { close(cancelled) })
		close(done)
	}()
	<-clk.timers // first poll saw no HALT and waits
	assert.Empty(t, hl.Halted())

	host.Files["main:.rr/HALT"] = []byte("x") // pushed 30 s into the interval
	clk.Advance(30 * time.Second)
	assert.Empty(t, hl.Halted(), "not polled yet")
	clk.Advance(30 * time.Second) // 60 s after start
	<-cancelled
	<-done
	assert.Contains(t, hl.Halted(), "kill switch")
}

func TestPollStopsOnContext(t *testing.T) {
	clk := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	var hl Halter
	done := make(chan struct{})
	go func() {
		hl.Poll(ctx, clk, time.Minute, func(context.Context) error { return nil }, nil)
		close(done)
	}()
	<-clk.timers
	cancel()
	<-done
	assert.Empty(t, hl.Halted())
}

func TestSocketServerAndClient(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "h.sock")
	var hl Halter
	stop, err := hl.Serve(sock)
	require.NoError(t, err)
	defer stop()
	c := Client{Path: sock}
	assert.Empty(t, c.Halted())
	hl.set("kill switch present\nmultiline")
	assert.Equal(t, "kill switch present multiline", c.Halted())
	stop()
	assert.NotEmpty(t, c.Halted(), "no runner = halted (fail-closed)")
}
