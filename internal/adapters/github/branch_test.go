package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRejectsBadDefaultBranch(t *testing.T) {
	for _, b := range []string{"-x", "a..b", "main;rm", "a b", "$(x)"} {
		in := input(t, t.TempDir())
		in.Policy.Policy.Project.DefaultBranch = b
		_, err := gen{}.Render(context.Background(), in)
		assert.Error(t, err, b)
	}
	in := input(t, t.TempDir())
	in.Policy.Policy.Project.DefaultBranch = "release/1.x"
	_, err := gen{}.Render(context.Background(), in)
	assert.NoError(t, err)
}
