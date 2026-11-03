package plan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRefusesBadTests(t *testing.T) {
	for name, tc := range map[string]struct{ test, want string }{
		"dotdot":   {"../../etc/x", "escapes"},
		"absolute": {"/etc/passwd", "absolute"},
		"glob":     {"a_*_test.go", "glob"},
	} {
		t.Run(name, func(t *testing.T) {
			st := s("a", []string{"a.go"})
			st.Tests = []string{tc.test}
			err := Check(Plan{Steps: []Step{st}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
	st := s("a", []string{"a.go"})
	st.Tests = []string{"./a_test.go"}
	p, err := normalize(Plan{Steps: []Step{st}})
	require.NoError(t, err)
	assert.Equal(t, []string{"a_test.go"}, p.Steps[0].Tests)
	assert.Equal(t, []string{"a.go"}, p.Steps[0].Files)
}

// Step tests are writable, so unordered steps must not share a test file.
func TestCheckRefusesSharedTestsWithoutAfter(t *testing.T) {
	a, b := s("a", []string{"a.go"}), s("b", []string{"b.go"})
	a.Tests, b.Tests = []string{"x_test.go"}, []string{"x_test.go"}
	err := Check(Plan{Steps: []Step{a, b}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "share")
	b.After = []string{"a"}
	require.NoError(t, Check(Plan{Steps: []Step{a, b}}))
}
