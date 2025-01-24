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
		{"debian", "testdata/osv-scanner-release.json", []byte{}, false, func(t *testing.T, pred *Predicate) {
			t.Helper()
			require.NotNil(t, pred.GetParsed())
			require.NotNil(t, pred.Parsed.Date)
			require.NotNil(t, pred.Parsed.Results)

			require.Len(t, pred.Parsed.Results, 1)
			require.Len(t, pred.Parsed.Results[0].Packages, 4)
			require.Len(t, pred.Parsed.Results[0].Packages[0].Vulnerabilities, 4)
			require.Len(t, pred.Parsed.Results[0].Packages[0].Vulnerabilities[0].Affected, 3)

			require.Equal(t, "GHSA-r9px-m959-cxf4", pred.Parsed.Results[0].Packages[0].Vulnerabilities[0].Id)
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
