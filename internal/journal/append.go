package journal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vanssata/agentic-risk-rails/internal/core"
)

// prepare checks the lifecycle rules for e and returns the prev hash for its line.
func (j *fileJournal) prepare(e core.Event, path string) (prev string, created bool, err error) {
	if exists(path) {
		if e.Type == "task_started" {
			return "", false, fmt.Errorf("journal: task %q already started", e.Task)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", false, err
		}
		lines := splitLines(data)
		if len(lines) == 0 {
			return GenesisPrev, false, nil
		}
		return hashHex(lines[len(lines)-1]), false, nil
	}
	if e.Type != "task_started" {
		return "", false, fmt.Errorf("journal: task %q is not open", e.Task)
	}
	if exists(filepath.Join(TasksDir(j.root), e.Task+".jsonl")) {
		return "", false, fmt.Errorf("journal: task %q is already closed", e.Task)
	}
	open, err := openTasks(j.root)
	if err != nil {
		return "", false, err
	}
	if len(open) > 0 {
		return "", false, &core.Refusal{Code: "TASK_IN_FLIGHT", Detail: "task " + open[0] + " is open in this checkout"}
	}
	if err := os.MkdirAll(RunDir(j.root), 0o755); err != nil {
		return "", false, err
	}
	return GenesisPrev, true, nil
}

// appendLine writes one line with O_APPEND and fsyncs it.
func appendLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
