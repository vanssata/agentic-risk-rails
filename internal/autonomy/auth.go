package autonomy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// authFiles is the credentials file of a subscription login in the runtime's
// config dir (CLAUDE_CONFIG_DIR, CODEX_HOME). docs/research/verified/runner.md.
var authFiles = map[string]string{"claude": ".credentials.json", "codex": "auth.json"}

// claudeHome is CLAUDE_CONFIG_DIR in the agent container when a login is staged.
const claudeHome = "/tmp/.claude"

// SubscriptionHosts are the hosts a runtime's CLI needs with a subscription login
// (rr run --auth-from) instead of an API key.
func SubscriptionHosts(runtime string) []string {
	switch runtime {
	case "claude":
		return []string{"api.anthropic.com", "platform.claude.com"}
	case "codex":
		return []string{"chatgpt.com", "auth.openai.com"}
	}
	return nil
}

// stageAuth copies the credentials file of the isolated login d.AuthFrom (e.g.
// ~/.claude-rr, never the user's own config dir) into a fresh runner-owned dir that
// one agent container mounts as its config dir. done removes the dir and writes a
// token the runtime refreshed back to AuthFrom, but only a regular file that is a
// JSON object with the same top-level keys; anything else is an error (the task blocks).
func (d DockerRunner) stageAuth() (dir string, done func() error, err error) {
	name, ok := authFiles[d.Runtime]
	if !ok {
		return "", nil, fmt.Errorf("docker runner: no subscription login for runtime %q", d.Runtime)
	}
	src := filepath.Join(d.AuthFrom, name)
	orig, err := os.ReadFile(src)
	if err != nil {
		return "", nil, fmt.Errorf("docker runner: login %s: %w", d.AuthFrom, err)
	}
	keys, err := topKeys(orig)
	if err != nil {
		return "", nil, fmt.Errorf("docker runner: login %s: %w", src, err)
	}
	if err := os.MkdirAll(d.StateDir, 0o700); err != nil {
		return "", nil, err
	}
	if dir, err = os.MkdirTemp(d.StateDir, "auth-"); err != nil {
		return "", nil, err
	}
	staged := filepath.Join(dir, name)
	if err := os.WriteFile(staged, orig, 0o600); err != nil { //nolint:gosec // runner-owned MkdirTemp dir
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	done = func() error {
		defer func() { _ = os.RemoveAll(dir) }()
		fi, err := os.Lstat(staged)
		if err != nil {
			return nil // removed in the container: the login stays as it was
		}
		now, err := os.ReadFile(staged)
		if err != nil || bytes.Equal(now, orig) {
			return err
		}
		if k, kerr := topKeys(now); !fi.Mode().IsRegular() || kerr != nil || !slices.Equal(k, keys) {
			return fmt.Errorf("docker runner: %s changed in the container but is not a login: %s kept", name, src)
		}
		tmp := src + ".rr-tmp"
		if err := os.WriteFile(tmp, now, 0o600); err != nil { //nolint:gosec // AuthFrom is the operator's --auth-from
			return err
		}
		return os.Rename(tmp, src)
	}
	return dir, done, nil
}

func topKeys(b []byte) ([]string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys, nil
}
