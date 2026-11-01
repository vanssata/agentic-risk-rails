package autonomy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

// anchor keeps an authoritative copy of each task's in-sandbox journal outside
// the sandbox. The chain has no key, so `.rr` is only as trusted as the sandbox:
// a later wave checks that every live journal still starts with the bytes the
// runner saw (an append-only file only grows).
type anchor struct {
	root string // checkout, where the agent writes .rr
	dir  string // runner state dir, outside the sandbox
	run  string // run id: copies of other runs are not ours
}

func (a anchor) live(task string) (string, error) {
	for _, p := range []string{filepath.Join(journal.RunDir(a.root), task+".jsonl"), filepath.Join(journal.TasksDir(a.root), task+".jsonl")} {
		if _, err := os.Lstat(p); err == nil {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

func (a anchor) prefix() string { return "journal-" + a.run + "-" }

func (a anchor) copyPath(task string) string { return filepath.Join(a.dir, a.prefix()+task+".jsonl") }

const maxJournal = 16 << 20

// readRegular reads a plain file of at most maxJournal bytes; a symlink or other type is an error.
func readRegular(p string) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxJournal {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", p, maxJournal)
	}
	return os.ReadFile(p)
}

// snapshot copies the task's journal and returns its head hash and size.
// ok=false: the agent wrote no journal.
func (a anchor) snapshot(task string) (head string, size int, ok bool, err error) {
	p, err := a.live(task)
	if os.IsNotExist(err) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	b, err := readRegular(p)
	if err != nil {
		return "", 0, false, fmt.Errorf("in-sandbox journal of %s: %w", task, err)
	}
	if err := journal.Verify(p); err != nil {
		return "", 0, false, fmt.Errorf("in-sandbox journal of %s: %w", task, err)
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return "", 0, false, err
	}
	if err := os.WriteFile(a.copyPath(task), b, 0o600); err != nil { //nolint:gosec // task ids are validated by taskIDRe
		return "", 0, false, err
	}
	head, err = journal.HeadHash(a.copyPath(task))
	return head, len(b), err == nil, err
}

// verify checks every copy against its live journal. Any problem is a mismatch.
func (a anchor) verify() error {
	copies, err := filepath.Glob(filepath.Join(a.dir, a.prefix()+"*.jsonl"))
	if err != nil {
		return err
	}
	for _, c := range copies {
		task := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(c), a.prefix()), ".jsonl")
		want, err := os.ReadFile(c)
		if err != nil {
			return err
		}
		lp, err := a.live(task)
		if err != nil {
			return fmt.Errorf("journal of %s vanished from the sandbox: %w", task, err)
		}
		got, err := readRegular(lp)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(got, want) {
			return fmt.Errorf("journal of %s no longer extends the runner's copy", task)
		}
	}
	return nil
}
