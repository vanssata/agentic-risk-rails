package plan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func s(id string, files []string, after ...string) Step {
	return Step{ID: id, Files: files, After: after}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		steps   []Step
		wantErr string
	}{
		{"disjoint ok", []Step{s("a", []string{"a.go"}), s("b", []string{"b.go"})}, ""},
		{"overlap without after", []Step{s("a", []string{"x.go"}), s("b", []string{"x.go"})}, "share"},
		{"overlap with after", []Step{s("a", []string{"x.go"}), s("b", []string{"x.go"}, "a")}, ""},
		{"overlap ordered transitively", []Step{s("a", []string{"x.go"}), s("m", []string{"m.go"}, "a"), s("b", []string{"x.go"}, "m")}, ""},
		{"cycle", []Step{s("a", []string{"a.go"}, "b"), s("b", []string{"b.go"}, "a")}, "cycle"},
		{"self cycle", []Step{s("a", []string{"a.go"}, "a")}, "cycle"},
		{"unknown after", []Step{s("a", []string{"a.go"}, "zz")}, "unknown after"},
		{"duplicate id", []Step{s("a", []string{"a.go"}), s("a", []string{"b.go"})}, "duplicate"},
		{"no files", []Step{s("a", nil)}, "no files"},
		{"no id", []Step{s("", []string{"a.go"})}, "without id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(Plan{Steps: tc.steps})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func ids(w [][]Step) [][]string {
	out := [][]string{}
	for _, wave := range w {
		var r []string
		for _, st := range wave {
			r = append(r, st.ID)
		}
		out = append(out, r)
	}
	return out
}

func TestWaves(t *testing.T) {
	tests := []struct {
		name  string
		steps []Step
		want  [][]string
	}{
		{"independent in one wave", []Step{s("a", []string{"a"}), s("b", []string{"b"})}, [][]string{{"a", "b"}}},
		{"chain", []Step{s("a", []string{"x"}), s("b", []string{"x"}, "a"), s("c", []string{"x"}, "b")}, [][]string{{"a"}, {"b"}, {"c"}}},
		{"diamond", []Step{s("d", []string{"d"}, "b", "c"), s("a", []string{"a"}), s("b", []string{"b"}, "a"), s("c", []string{"c"}, "a")},
			[][]string{{"a"}, {"b", "c"}, {"d"}}},
		{"long path decides level", []Step{s("a", []string{"a"}), s("b", []string{"b"}, "a"), s("c", []string{"c"}, "a", "b")},
			[][]string{{"a"}, {"b"}, {"c"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := Waves(Plan{Steps: tc.steps})
			require.NoError(t, err)
			assert.Equal(t, tc.want, ids(w))
			// invariant: no file shared inside a wave
			for _, wave := range w {
				seen := map[string]bool{}
				for _, st := range wave {
					for _, f := range st.Files {
						assert.False(t, seen[f], f)
						seen[f] = true
					}
				}
			}
		})
	}
	_, err := Waves(Plan{Steps: []Step{s("a", []string{"x"}), s("b", []string{"x"})}})
	assert.Error(t, err)
}

func TestParse(t *testing.T) {
	p, err := Parse([]byte("steps:\n  - id: a\n    files: [a.go]\n    tests: [a_test.go]\n  - id: b\n    files: [b.go]\n    after: [a]\n"))
	require.NoError(t, err)
	require.NoError(t, Check(p))
	assert.Equal(t, []string{"a"}, p.Steps[1].After)
	_, err = Parse([]byte("steps:\n  - id: a\n    bogus: 1\n"))
	assert.Error(t, err)
}
