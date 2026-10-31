// Package plan: the implementation plan as a DAG of steps with file ownership
// (DES §6). A wave is a set of steps with no file overlap.
package plan

import (
	"bytes"
	"errors"
	"fmt"

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

// Check validates ids, after references, cycles and file ownership: two steps
// sharing a file must be ordered by (transitive) after.
func Check(p Plan) error {
	_, err := analyse(p)
	return err
}

// Waves groups a checked plan into waves (longest-path levels), each in plan order.
func Waves(p Plan) ([][]Step, error) {
	level, err := analyse(p)
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
func analyse(p Plan) ([]int, error) {
	idx := map[string]int{}
	for i, s := range p.Steps {
		if s.ID == "" {
			return nil, errors.New("plan: step without id")
		}
		if _, dup := idx[s.ID]; dup {
			return nil, fmt.Errorf("plan: duplicate step %q", s.ID)
		}
		if len(s.Files) == 0 {
			return nil, fmt.Errorf("plan: step %q owns no files", s.ID)
		}
		idx[s.ID] = i
	}
	for _, s := range p.Steps {
		for _, a := range s.After {
			if _, ok := idx[a]; !ok {
				return nil, fmt.Errorf("plan: step %q: unknown after %q", s.ID, a)
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
			return nil, err
		}
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if reach[i][j] || reach[j][i] {
				continue
			}
			if f := shared(p.Steps[i].Files, p.Steps[j].Files); f != "" {
				return nil, fmt.Errorf("plan: steps %q and %q share %q: add after", p.Steps[i].ID, p.Steps[j].ID, f)
			}
		}
	}
	return level, nil
}

func shared(a, b []string) string {
	set := map[string]bool{}
	for _, f := range a {
		set[f] = true
	}
	for _, f := range b {
		if set[f] {
			return f
		}
	}
	return ""
}
