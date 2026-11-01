package verify

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithSandboxRewritesEveryCommand(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name    string
		sb      Sandbox
		wantArg []string
		wantErr string
	}{
		{"wrapped", func(a []string) ([]string, error) { return append([]string{"sh", "-c", "exit 0", "--"}, a...), nil },
			[]string{"-c", "exit 0", "--", "vendor/bin/phpunit", "--x"}, ""},
		{"error", func([]string) ([]string, error) { return nil, errors.New("no image") }, nil, "no image"},
		{"path not allowed", func(a []string) ([]string, error) { return append([]string{"./docker"}, a...), nil }, nil, "bare command"},
		{"empty", func([]string) ([]string, error) { return nil, nil }, nil, "bare command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := hostCmd(WithSandbox(context.Background(), tt.sb), root, "vendor/bin/phpunit", "--x")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantArg, c.Args[1:])
			assert.Equal(t, root, c.Dir)
		})
	}
}
