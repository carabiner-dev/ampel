package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFetchedRef(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		data    string
		mustErr bool
	}{
		{"policy", `{"id": "policyset-id", "tenets": [] }`, false},
		{"policySet", `{"id": "policyset-id", "policies": [] }`, false},
		{"other", `{"fan": "dango"}`, true},
		{"invalid json", `"fan": "dango"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseFetchedRef([]byte(tc.data))
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}

}
