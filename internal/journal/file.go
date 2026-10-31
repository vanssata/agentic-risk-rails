package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/projection"
)

// SchemaVersion is the event schema written by this package.
const SchemaVersion = 1

// RunDir is where open tasks live; TasksDir holds closed ones.
func RunDir(root string) string   { return filepath.Join(root, ".rr", "run") }
func TasksDir(root string) string { return filepath.Join(root, ".rr", "tasks") }

// GenesisPrev is PrevSHA256 of the first line of every task: sha256 of the empty string.
var GenesisPrev = hashHex(nil)

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type fileJournal struct {
	root string
	now  func() time.Time
}

// New returns the file journal under <root>/.rr.
func New(root string) core.Journal { return NewWithClock(root, nil) }

// NewWithClock is New with an injectable clock (nil = time.Now in UTC).
func NewWithClock(root string, now func() time.Time) core.Journal {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &fileJournal{root: root, now: now}
}

// lock takes the exclusive checkout-wide journal lock (.rr/.lock). One lock,
// not one per task file, because the in-flight check spans files and Close renames them.
func (j *fileJournal) lock() (unlock func(), err error) {
	if err := os.MkdirAll(filepath.Join(j.root, ".rr"), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(j.root, ".rr", ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil // closing releases the flock
}

func validTask(t string) error {
	if t == "" || t == "." || t == ".." || strings.ContainsAny(t, `/\`+"\x00") || strings.HasPrefix(t, ".") {
		return fmt.Errorf("journal: invalid task id %q", t)
	}
	return nil
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func (j *fileJournal) Append(ctx context.Context, e core.Event) (core.Event, error) {
	if err := ctx.Err(); err != nil {
		return core.Event{}, err
	}
	if _, ok := Lookup(e.Type); !ok {
		return core.Event{}, fmt.Errorf("journal: event type %q is not registered", e.Type)
	}
	if err := validTask(e.Task); err != nil {
		return core.Event{}, err
	}
	unlock, err := j.lock()
	if err != nil {
		return core.Event{}, fmt.Errorf("journal: lock: %w", err)
	}
	defer unlock()

	path := filepath.Join(RunDir(j.root), e.Task+".jsonl")
	prev := GenesisPrev
	created := false
	switch {
	case exists(path):
		if e.Type == "task_started" {
			return core.Event{}, fmt.Errorf("journal: task %q already started", e.Task)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return core.Event{}, err
		}
		lines := splitLines(data)
		if len(lines) > 0 {
			prev = hashHex(lines[len(lines)-1])
		}
	case e.Type != "task_started":
		return core.Event{}, fmt.Errorf("journal: task %q is not open", e.Task)
	default:
		if exists(filepath.Join(TasksDir(j.root), e.Task+".jsonl")) {
			return core.Event{}, fmt.Errorf("journal: task %q is already closed", e.Task)
		}
		open, err := openTasks(j.root)
		if err != nil {
			return core.Event{}, err
		}
		if len(open) > 0 {
			return core.Event{}, &core.Refusal{Code: "TASK_IN_FLIGHT", Detail: "task " + open[0] + " is open in this checkout"}
		}
		if err := os.MkdirAll(RunDir(j.root), 0o755); err != nil {
			return core.Event{}, err
		}
		created = true
	}

	if e.Schema == 0 {
		e.Schema = SchemaVersion
	}
	e.Time = j.now()
	e.PrevSHA256 = prev
	line, err := json.Marshal(e)
	if err != nil {
		return core.Event{}, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return core.Event{}, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return core.Event{}, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return core.Event{}, err
	}
	if err := f.Close(); err != nil {
		return core.Event{}, err
	}
	if created {
		if err := fsyncDir(RunDir(j.root)); err != nil {
			return core.Event{}, err
		}
	}
	return e, nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(data, []byte("\n")) {
		if len(l) > 0 {
			out = append(out, l)
		}
	}
	return out
}

func openTasks(root string) ([]string, error) {
	m, err := filepath.Glob(filepath.Join(RunDir(root), "*.jsonl"))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(m))
	for _, p := range m {
		out = append(out, strings.TrimSuffix(filepath.Base(p), ".jsonl"))
	}
	return out, nil
}

func (j *fileJournal) Open(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openTasks(j.root)
}

// ReadFile parses a journal file. Unknown JSON fields are ignored; events with
// a newer schema are returned as-is (Data intact).
func ReadFile(path string) ([]core.Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []core.Event
	for i, l := range splitLines(data) {
		var e core.Event
		if err := json.Unmarshal(l, &e); err != nil {
			return nil, fmt.Errorf("journal: %s line %d: %w", path, i+1, err)
		}
		out = append(out, e)
	}
	return out, nil
}

func (j *fileJournal) Events(ctx context.Context, task string) ([]core.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validTask(task); err != nil {
		return nil, err
	}
	for _, dir := range []string{RunDir(j.root), TasksDir(j.root)} {
		p := filepath.Join(dir, task+".jsonl")
		if exists(p) {
			return ReadFile(p)
		}
	}
	return nil, fmt.Errorf("journal: unknown task %q", task)
}

func (j *fileJournal) Close(ctx context.Context, task string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validTask(task); err != nil {
		return err
	}
	unlock, err := j.lock()
	if err != nil {
		return fmt.Errorf("journal: lock: %w", err)
	}
	defer unlock()

	src := filepath.Join(RunDir(j.root), task+".jsonl")
	if !exists(src) {
		return fmt.Errorf("journal: task %q is not open", task)
	}
	events, err := ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(TasksDir(j.root), task), 0o755); err != nil {
		return err
	}
	md := filepath.Join(TasksDir(j.root), task, "task.md")
	if err := os.WriteFile(md, []byte(projection.TaskMD(projection.Summarize(events))), 0o644); err != nil {
		return err
	}
	if err := os.Rename(src, filepath.Join(TasksDir(j.root), task+".jsonl")); err != nil {
		return err
	}
	if err := fsyncDir(TasksDir(j.root)); err != nil {
		return err
	}
	return fsyncDir(RunDir(j.root))
}

// Verify walks the hash chain of a journal file and reports the first broken
// line (1-based): a line that is not valid JSON, or whose prev_sha256 differs
// from the hash of the previous line's exact bytes. Editing line N is therefore
// reported at N+1; editing the last line is not detectable by the chain alone.
func Verify(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	prev := GenesisPrev
	for i, l := range splitLines(data) {
		var e core.Event
		if err := json.Unmarshal(l, &e); err != nil {
			return fmt.Errorf("%s: line %d: invalid JSON: %w", path, i+1, err)
		}
		if e.PrevSHA256 != prev {
			return fmt.Errorf("%s: line %d: %w", path, i+1, ErrChainBroken)
		}
		prev = hashHex(l)
	}
	return nil
}

// ErrChainBroken is wrapped by Verify when prev_sha256 does not match.
var ErrChainBroken = errors.New("hash chain broken")
