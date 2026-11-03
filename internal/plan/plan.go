// Package plan: the implementation plan as a DAG of steps with file ownership
// (DES §6). A wave is a set of steps with no file overlap.
package plan

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Step declares the files it owns (exact repo-relative paths), its tests and
// the steps it must follow.
type Step struct {
	ID    string   `yaml:"id"`
	Brief string   `yaml:"brief,omitempty"`
	Files []string `yaml:"files"`
	Tests []string `yaml:"tests,omitempty"`
	After []string `yaml:"after,omitempty"`
}

type Plan struct {
	Steps []Step `yaml:"steps"`
}

// Parse reads a plan; unknown keys are an error.
func Parse(raw []byte) (Plan, error) {
	var p Plan
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Plan{}, fmt.Errorf("plan: %w", err)
	}
	return p, nil
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*$`)

// ValidID: step ids and task names become branch and directory names.
func ValidID(id string) bool { return idPattern.MatchString(id) && id != "." && id != ".." }

// Check validates ids, after references, cycles and file ownership: two steps
// sharing a file must be ordered by (transitive) after.
func Check(p Plan) error {
	_, _, err := analyse(p)
	return err
}

// Waves groups a checked plan into waves (longest-path levels), each in plan order.
func Waves(p Plan) ([][]Step, error) {
	p, level, err := analyse(p)
	if err != nil {
		return nil, err
	}
	var out [][]Step
	for i, s := range p.Steps {
		for len(out) <= level[i] {
			out = append(out, nil)
		}
		out[level[i]] = append(out[level[i]], s)
	}
	return out, nil
}

// analyse validates the plan and returns each step's wave level.
func analyse(p Plan) (Plan, []int, error) {
	p, err := normalize(p)
	if err != nil {
		return p, nil, err
	}
	idx := map[string]int{}
	for i, s := range p.Steps {
		if s.ID == "" {
			return p, nil, errors.New("plan: step without id")
		}
		if !ValidID(s.ID) {
			return p, nil, fmt.Errorf("plan: invalid step id %q", s.ID)
		}
		if _, dup := idx[s.ID]; dup {
			return p, nil, fmt.Errorf("plan: duplicate step %q", s.ID)
		}
		if len(s.Files) == 0 {
			return p, nil, fmt.Errorf("plan: step %q owns no files", s.ID)
		}
		idx[s.ID] = i
	}
	for _, s := range p.Steps {
		for _, a := range s.After {
			if _, ok := idx[a]; !ok {
				return p, nil, fmt.Errorf("plan: step %q: unknown after %q", s.ID, a)
			}
		}
	}
	n := len(p.Steps)
	level := make([]int, n)
	reach := make([]map[int]bool, n) // transitive predecessors
	state := make([]int, n)          // 0 new, 1 visiting, 2 done
	var visit func(i int) error
	visit = func(i int) error {
		switch state[i] {
		case 1:
			return fmt.Errorf("plan: cycle through step %q", p.Steps[i].ID)
		case 2:
			return nil
		}
		state[i] = 1
		reach[i] = map[int]bool{}
		for _, a := range p.Steps[i].After {
			j := idx[a]
			if err := visit(j); err != nil {
				return err
			}
			reach[i][j] = true
			for k := range reach[j] {
				reach[i][k] = true
			}
			level[i] = max(level[i], level[j]+1)
		}
		state[i] = 2
		return nil
	}
	for i := range p.Steps {
		if err := visit(i); err != nil {
			return p, nil, err
		}
	}
	return p, level, unorderedOverlap(p, reach)
}

// unorderedOverlap fails if two steps not ordered by after share a path.
func unorderedOverlap(p Plan, reach []map[int]bool) error {
	for i := range p.Steps {
		for j := i + 1; j < len(p.Steps); j++ {
			if reach[i][j] || reach[j][i] {
				continue
			}
			a := append(append([]string{}, p.Steps[i].Files...), p.Steps[i].Tests...)
			b := append(append([]string{}, p.Steps[j].Files...), p.Steps[j].Tests...)
			if f := shared(a, b); f != "" {
				return fmt.Errorf("plan: steps %q and %q share %q: add after", p.Steps[i].ID, p.Steps[j].ID, f)
			}
		}
	}
	return nil
}

// shared returns a path of a that is equal to, inside, or a directory
// prefix of a path of b.
func shared(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			if x == y || strings.HasPrefix(y, x+"/") || strings.HasPrefix(x, y+"/") {
				return x
			}
		}
	}
	return ""
}

// normalize returns a copy of p with every file path cleaned. A path must be
// relative, free of "..", pathspec magic (leading ':') and glob characters.
func normalize(p Plan) (Plan, error) {
	out := Plan{Steps: make([]Step, len(p.Steps))}
	for i, s := range p.Steps {
		out.Steps[i] = s
		out.Steps[i].Files = make([]string, len(s.Files))
		if s.Tests != nil {
			out.Steps[i].Tests = make([]string, len(s.Tests))
		}
		for j, f := range append(append([]string{}, s.Files...), s.Tests...) {
			c := path.Clean(filepath.ToSlash(f))
			switch {
			case f == "" || c == ".":
				return p, fmt.Errorf("plan: step %q: empty path", s.ID)
			case path.IsAbs(c) || filepath.IsAbs(f):
				return p, fmt.Errorf("plan: step %q: absolute path %q", s.ID, f)
			case strings.HasPrefix(f, ":"):
				return p, fmt.Errorf("plan: step %q: pathspec magic in %q", s.ID, f)
			case strings.ContainsAny(f, "*?[]{}\\"):
				return p, fmt.Errorf("plan: step %q: glob character in %q", s.ID, f)
			}
			for _, seg := range strings.Split(filepath.ToSlash(f), "/") {
				if seg == ".." {
					return p, fmt.Errorf("plan: step %q: %q escapes the repository", s.ID, f)
				}
			}
			if j < len(s.Files) {
				out.Steps[i].Files[j] = c
			} else {
				out.Steps[i].Tests[j-len(s.Files)] = c
			}
		}
	}
	return out, nil
}
