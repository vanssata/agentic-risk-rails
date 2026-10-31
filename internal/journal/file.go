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
	"regexp"
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
	f, err := os.OpenFile(filepath.Join(j.root, ".rr", ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil // closing releases the flock
}

var headRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

var taskIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validTask(t string) error {
	if !taskIDRe.MatchString(t) || strings.HasSuffix(t, ".jsonl") {
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
	prev, created, err := j.prepare(e, path)
	if err != nil {
		return core.Event{}, err
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
	if err := appendLine(path, line); err != nil {
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
	if err := Verify(src); err != nil {
		return err
	}
	events, err := ReadFile(src)
	if err != nil {
		return err
	}
	for i, e := range events {
		if _, ok := Lookup(e.Type); !ok {
			return fmt.Errorf("journal: %s line %d: unregistered type %q", src, i+1, e.Type)
		}
		if e.Task != task {
			return fmt.Errorf("journal: %s line %d: event of task %q in file of task %q", src, i+1, e.Task, task)
		}
	}
	head, err := HeadHash(src)
	if err != nil {
		return err
	}
	sum := projection.Summarize(events)
	sum.Head = head
	taskDir := filepath.Join(TasksDir(j.root), task)
	firstTasks := !exists(TasksDir(j.root))
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		return err
	}
	if firstTasks {
		if err := fsyncDir(filepath.Join(j.root, ".rr")); err != nil {
			return err
		}
	}
	if err := writeSynced(filepath.Join(taskDir, "task.md"), []byte(projection.TaskMD(sum))); err != nil {
		return err
	}
	if err := fsyncDir(taskDir); err != nil {
		return err
	}
	if err := fsyncDir(TasksDir(j.root)); err != nil {
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
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return fmt.Errorf("%s: %w", path, ErrTornTail)
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

// ErrTornTail means the file does not end in a newline (a crash mid-write).
var ErrTornTail = errors.New("torn tail: last line is not newline-terminated")

// HashLine is the chain hash of one line's exact bytes (no newline).
func HashLine(l []byte) string { return hashHex(l) }

// HeadHash is the sha256 of the last line of a journal file: the anchor Close records.
func HeadHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := splitLines(data)
	if len(lines) == 0 {
		return GenesisPrev, nil
	}
	return hashHex(lines[len(lines)-1]), nil
}

// ReadHead returns the head hash recorded in a closed task's task.md.
func ReadHead(root, task string) (string, error) {
	b, err := os.ReadFile(filepath.Join(TasksDir(root), task, "task.md"))
	if err != nil {
		return "", err
	}
	head := ""
	for _, l := range strings.Split(string(b), "\n") {
		if h, ok := strings.CutPrefix(l, "- head: "); ok {
			head = h // the LAST head line wins
		}
	}
	if !headRe.MatchString(head) {
		return "", fmt.Errorf("journal: no anchor in task.md of %q", task)
	}
	return head, nil
}

// Repair truncates a trailing partial line, but only if that partial line is
// not valid JSON. It takes the journal lock and first saves the removed bytes
// to <path>.torn.<unix-nanos>. It returns the removed bytes (nil if unchanged).
func Repair(root, path string) ([]byte, error) {
	unlock, err := (&fileJournal{root: root}).lock()
	if err != nil {
		return nil, fmt.Errorf("journal: lock: %w", err)
	}
	defer unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return nil, nil
	}
	cut := bytes.LastIndexByte(data, '\n') + 1
	removed := data[cut:]
	if json.Valid(removed) {
		return nil, fmt.Errorf("%s: unterminated last line is valid JSON; not truncating", path)
	}
	if err := writeSynced(fmt.Sprintf("%s.torn.%d", path, time.Now().UnixNano()), removed); err != nil {
		return nil, err
	}
	if err := os.Truncate(path, int64(cut)); err != nil {
		return nil, err
	}
	return removed, fsyncDir(filepath.Dir(path))
}

func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
