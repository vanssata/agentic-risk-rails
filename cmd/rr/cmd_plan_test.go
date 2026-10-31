package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlanCheck(t *testing.T) {
	tests := []struct {
		name, yaml, wantOut, wantErr string
	}{
		{"waves", "steps:\n- {id: a, files: [x]}\n- {id: b, files: [x], after: [a]}\n- {id: c, files: [y]}\n", "wave 1: a c\nwave 2: b\n", ""},
		{"overlap", "steps:\n- {id: a, files: [x]}\n- {id: b, files: [x]}\n", "", "share"},
		{"cycle", "steps:\n- {id: a, files: [x], after: [b]}\n- {id: b, files: [y], after: [a]}\n", "", "cycle"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "plan.yaml")
			require.NoError(t, os.WriteFile(f, []byte(tc.yaml), 0o644))
			out, err := runRR("plan", "check", "--file", f)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantOut, out)
		})
	}
}
