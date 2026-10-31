package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PriorArtTTL is the prior-art cache lifetime (DES §5.5).
const PriorArtTTL = 7 * 24 * time.Hour

var shaRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// Entry is one cached scout result: <dir>/<sha>/<role>-<qhash>.json.
type Entry struct {
	SHA      string    `json:"sha"`
	Role     string    `json:"role"`
	QHash    string    `json:"qhash"`
	Body     string    `json:"body"`
	Read     []string  `json:"read"`
	LockHash string    `json:"lock_hash"`
	At       time.Time `json:"at"`
}

// Inv is what changed since the entry's sha, supplied by the caller. Changed must come from
// `git diff --name-only --no-renames <sha>..HEAD` plus uncommitted changes, so that a rename
// or deletion lists the old path. Root (optional) is the repo root, stripped from absolute READ paths.
type Inv struct {
	Root     string
	Changed  []string
	LockHash string
	Now      time.Time
}

// QHash is sha256 of the question.
func QHash(question string) string {
	h := sha256.Sum256([]byte(question))
	return hex.EncodeToString(h[:])
}

// RepoDir expands the policy cache dir: ~ to home and <repo-hash> to a hash of the repo root.
func RepoDir(tmpl, home, repoRoot string) string {
	h := sha256.Sum256([]byte(repoRoot))
	tmpl = strings.ReplaceAll(tmpl, "<repo-hash>", hex.EncodeToString(h[:8]))
	if strings.HasPrefix(tmpl, "~/") {
		tmpl = filepath.Join(home, tmpl[2:])
	}
	return tmpl
}

func entryPath(dir, sha, role, qhash string) (string, error) {
	if !shaRe.MatchString(sha) || !validRole(role) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(qhash) {
		return "", fmt.Errorf("research: bad cache key (%q, %q, %q)", sha, role, qhash)
	}
	return filepath.Join(dir, sha, role+"-"+qhash+".json"), nil
}

// Put writes the entry atomically.
func Put(dir string, e Entry) error {
	p, err := entryPath(dir, e.SHA, e.Role, e.QHash)
	if err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(b)
	if err := errors.Join(werr, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Get returns a still-valid entry. A missing, unreadable or invalidated entry is a miss.
func Get(dir, sha, role, qhash string, inv Inv) (Entry, bool, error) {
	p, err := entryPath(dir, sha, role, qhash)
	if err != nil {
		return Entry{}, false, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil || e.SHA != sha || e.Role != role || e.QHash != qhash {
		return Entry{}, false, nil //nolint:nilerr // a corrupt entry is a cache miss
	}
	return e, Valid(e, inv), nil
}

// Valid applies the DES §5.5 invalidation rules per role. Unknown roles are invalid.
func Valid(e Entry, inv Inv) bool {
	switch e.Role {
	case "code", "test":
		return len(e.Read) > 0 && !touches(e, inv)
	case "tech-docs":
		return e.LockHash == inv.LockHash
	case "prior-art":
		return inv.Now.Sub(e.At) < PriorArtTTL
	case "project-docs":
		if len(e.Read) == 0 || touches(e, inv) {
			return false
		}
		for _, c := range inv.Changed {
			if strings.HasPrefix(c, "docs/") {
				return false
			}
		}
		return true
	}
	return false // history is always fresh
}

// normRead strips :line, a leading ./ and the repo root from a path.
func normRead(p, root string) string {
	p = lineSuffix.ReplaceAllString(strings.TrimSpace(p), "")
	if root != "" {
		p = strings.TrimPrefix(p, strings.TrimSuffix(root, "/")+"/")
	}
	p = strings.TrimPrefix(p, "./")
	return strings.TrimSuffix(p, "/")
}

// touches reports whether any changed path equals a READ path or lies under a READ directory.
func touches(e Entry, inv Inv) bool {
	for _, r := range e.Read {
		r = normRead(r, inv.Root)
		for _, c := range inv.Changed {
			if c = normRead(c, inv.Root); c == r || strings.HasPrefix(c, r+"/") {
				return true
			}
		}
	}
	return false
}
