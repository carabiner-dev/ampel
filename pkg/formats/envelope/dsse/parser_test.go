package dsse

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fileName string
		mustErr  bool
	}{
		{
			name:     "normal",
			fileName: "testdata/single.dsse.json",
		},
	} {
		t.Parallel()
		t.Run(tc.name, func(t *testing.T) {
			p := Parser{}
			f, err := os.Open(tc.fileName)
			require.NoError(t, err)

			res, err := p.ParseStream(f)
			if tc.mustErr {
				require.Error(t, err)
			}
			require.NoError(t, err)
			require.NotNil(t, res[0].GetSignatures())
			require.Len(t, res[0].GetSignatures(), 1)
			require.NotNil(t, res[0].GetStatement())
			require.NotNil(t, res[0].GetStatement().GetPredicate())
		})
	}
}
