package osv

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		path        string
		data        []byte
		mustErr     bool
		verifyParse func(*testing.T, *Predicate)
	}{
		{"debian", "testdata/osv-debian.json", []byte{}, false, func(t *testing.T, pred *Predicate) {
			require.NotNil(t, pred.GetParsed())
			require.NotNil(t, pred.Parsed.Date)
			require.NotNil(t, pred.Parsed.Records)
			require.Len(t, pred.Parsed.Records, 1)
			require.Equal(t, pred.Parsed.Records[0].Id, "DSA-3029-1")
			require.Equal(t, pred.Parsed.Records[0].Aliases[0], "CVE-2014-3616")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parser := &Parser{}
			data := tc.data
			var err error
			if len(data) == 0 && tc.path != "" {
				data, err = os.ReadFile(tc.path)
				require.NoError(t, err)
			}
			pred, err := parser.Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
			tpred, ok := pred.(*Predicate)
			require.True(t, ok)
			if tc.verifyParse != nil {
				tc.verifyParse(t, tpred)
			}
		})
	}
}
