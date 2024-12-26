package bare

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseStream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		file    string
		mustErr bool
	}{} {
		t.Parallel()
		t.Run(tc.name, func(t *testing.T) {
			p := Parser{}
			f, err := os.Open(tc.name)
			require.NoError(t, err)
			_, err = p.ParseStream(f)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
