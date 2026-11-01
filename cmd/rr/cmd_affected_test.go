package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vanssata/agentic-risk-rails/internal/testutil"
)

func TestAffectedPHPFixture(t *testing.T) {
	root := testutil.CopyFixture(t, "php-symfony")
	var got struct {
		Full      bool
		Reason    string
		Uncovered []string
		Tests     map[string][]string
	}

	out, err := runPolicyRR(t, "affected", "--root", root, "--phpunit", "src/Payment/PaymentService.php")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.False(t, got.Full)
	assert.Equal(t, []string{"tests/Payment/PaymentServiceTest.php"}, got.Tests["phpunit"])

	out, err = runPolicyRR(t, "affected", "--root", root, "--phpunit", "composer.lock", "src/Controller/HomeController.php")
	require.NoError(t, err)
	got.Tests = nil
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.True(t, got.Full)
	assert.NotEmpty(t, got.Reason)
	assert.Equal(t, []string{"composer.lock", "src/Controller/HomeController.php"}, got.Uncovered)

	_, err = runPolicyRR(t, "affected", "--root", root, "--mode", "bogus", "x")
	assert.Error(t, err)
}
