package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func runTriage(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := cli.Root("test")
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"triage"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestTriageFixture(t *testing.T) {
	repo := testutil.CopyFixture(t, "php-symfony")
	for name, args := range map[string][]string{
		"payment":   {"--files", "src/Payment/PaymentService.php", "--declare", "behaviour=1,novelty=0"},
		"composer":  {"--files", "composer.json", "--declare", "behaviour=0,domain=0"},
		"programme": {"--files", "templates/base.html.twig", "--declare", "behaviour=0,domain=0,novelty=0", "--spec"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runTriage(t, append(args, "--root", repo)...)
			require.NoError(t, err)
			testutil.Golden(t, "triage_"+name, []byte(out))
		})
	}
}

func TestTriageBadDeclare(t *testing.T) {
	repo := testutil.CopyFixture(t, "php-symfony")
	_, err := runTriage(t, "--files", "composer.json", "--declare", "scope=3", "--root", repo)
	assert.Error(t, err)
}
