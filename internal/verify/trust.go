package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vanssata/agentic-risk-rails/internal/core"
	"github.com/vanssata/agentic-risk-rails/internal/journal"
)

// Trust is what the close facts rely on, all taken from the hash-chained
// task_started event and never from the CLI.
type Trust struct {
	Scope    []string
	BaseSHA  string
	Manifest Manifest
}

// LoadTrust reads task_started.data {scope, base_sha, baseline}, loads
// .rr/run/<task>.baseline.json and checks its sha256 against `baseline`.
// Anything missing or mismatching is an error (facts and close refuse).
func LoadTrust(root, task string, events []core.Event) (Trust, error) {
	var d struct {
		Scope    []string `json:"scope"`
		BaseSHA  string   `json:"base_sha"`
		Baseline string   `json:"baseline"`
	}
	found := false
	for _, e := range events {
		if e.Type == "task_started" {
			if err := json.Unmarshal(e.Data, &d); err != nil {
				return Trust{}, fmt.Errorf("verify: task_started data: %w", err)
			}
			found = true
			break
		}
	}
	switch {
	case !found:
		return Trust{}, errors.New("verify: refusing: no task_started event")
	case d.Scope == nil:
		return Trust{}, errors.New("verify: refusing: task_started carries no scope")
	case !fullSHA.MatchString(d.BaseSHA):
		return Trust{}, errors.New("verify: refusing: task_started carries no valid base_sha")
	case d.Baseline == "":
		return Trust{}, errors.New("verify: refusing: task_started carries no baseline")
	}
	raw, err := os.ReadFile(filepath.Join(journal.RunDir(root), task+".baseline.json"))
	if err != nil {
		return Trust{}, fmt.Errorf("verify: refusing: baseline manifest: %w", err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != d.Baseline {
		return Trust{}, errors.New("verify: refusing: baseline manifest does not match task_started.baseline")
	}
	t := Trust{Scope: d.Scope, BaseSHA: d.BaseSHA}
	if err := json.Unmarshal(raw, &t.Manifest); err != nil {
		return Trust{}, fmt.Errorf("verify: refusing: baseline manifest: %w", err)
	}
	return t, nil
}

// TaskMode is the highest-ranked mode among task_started, weight_rescored and
// weight_amended (data.mode); modes only grow. task_started must carry a known mode.
func TaskMode(events []core.Event) (core.Mode, error) {
	best, started := core.Mode(""), false
	for _, e := range events {
		if e.Type != "task_started" && e.Type != "weight_rescored" && e.Type != "weight_amended" {
			continue
		}
		var d struct {
			Mode core.Mode `json:"mode"`
		}
		if json.Unmarshal(e.Data, &d) != nil || d.Mode.Rank() < 0 {
			if e.Type == "task_started" {
				break
			}
			continue
		}
		if e.Type == "task_started" {
			started = true
		}
		if best == "" || d.Mode.Rank() > best.Rank() {
			best = d.Mode
		}
	}
	if !started {
		return "", errors.New("verify: refusing: task_started carries no known mode")
	}
	return best, nil
}
