package autonomy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// Clock is injected so tests never sleep.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// MaxPoll is the longest allowed poll interval: HALT must stop a run within 60 s.
const MaxPoll = 60 * time.Second

// PollEvery is autonomy.kill_switch.poll_seconds, never above MaxPoll.
func PollEvery(p core.Policy) time.Duration {
	s := p.Autonomy.KillSwitch.PollSeconds
	if s == nil || *s <= 0 || time.Duration(*s)*time.Second > MaxPoll {
		return MaxPoll
	}
	return time.Duration(*s) * time.Second
}

// CheckHalt reads the kill-switch file from the default branch through the hosting
// API. nil = running. A present file is a halt; ErrNotFound is the only "absent";
// every other error is a halt (on_read_error: halt).
func CheckHalt(ctx context.Context, h core.Hosting, branch, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second) // a hung API is a halt
	defer cancel()
	_, err := h.ReadFile(ctx, branch, path)
	switch {
	case err == nil:
		return fmt.Errorf("kill switch %s is present on %s", path, branch)
	case errors.Is(err, core.ErrNotFound):
		return nil
	}
	return fmt.Errorf("kill switch unreadable (halt): %w", err)
}

// Halter holds the current halt state; the socket server and the runner read it.
type Halter struct {
	mu     sync.Mutex
	reason string
}

func (h *Halter) set(r string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reason == "" {
		h.reason = r
	}
}

// Halted returns the halt reason, or "" while running.
func (h *Halter) Halted() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reason
}

// Poll runs check now and then every `every` until it fails (then it records the
// halt and calls onHalt once) or ctx ends.
func (h *Halter) Poll(ctx context.Context, clk Clock, every time.Duration, check func(context.Context) error, onHalt func()) {
	for {
		if err := check(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			h.set(err.Error())
			if onHalt != nil {
				onHalt()
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-clk.After(every):
		}
	}
}

// Serve answers "halted?" on a unix socket outside the agent sandbox. Every
// connection gets one line: "ok" or "halt <reason>". The returned stop closes it.
// The hook connects with Client.
func (h *Halter) Serve(path string) (stop func(), err error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("halt socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			line := "ok\n"
			if r := h.Halted(); r != "" {
				line = "halt " + strings.ReplaceAll(r, "\n", " ") + "\n"
			}
			_, _ = c.Write([]byte(line))
			_ = c.Close()
		}
	}()
	return func() { _ = l.Close(); _ = os.Remove(path) }, nil
}

// Client is the hook side: it asks the runner whether the run is halted.
// Fail-closed: a missing socket, a timeout or any answer but "ok" is a halt.
type Client struct {
	Path    string
	Timeout time.Duration // 0 = 1 s
}

// Halted returns "" when the runner answered ok, else the reason to deny.
func (c Client) Halted() string {
	to := c.Timeout
	if to <= 0 {
		to = time.Second
	}
	conn, err := net.DialTimeout("unix", c.Path, to)
	if err != nil {
		return "runner unreachable: " + err.Error()
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(to))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "runner gave no answer: " + err.Error()
	}
	if strings.TrimSpace(line) == "ok" {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "halt"))
}
