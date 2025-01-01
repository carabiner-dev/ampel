package intoto

import (
	"os"
	"testing"

	"github.com/puerco/ampel/pkg/formats/predicate/json"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		dataFile string
		mustErr  bool
	}{
		{
			"normal", "testdata/sample.intoto.json", false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Parser{}
			data, err := os.ReadFile(tc.dataFile)
			require.NoError(t, err)
			res, err := p.Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.NotNil(t, res.GetPredicate())
			pred := res.GetPredicate()
			jsonPred, ok := pred.(*json.Predicate)
			require.True(t, ok)
			require.Equal(t, "https://github.com/Attestations/GitHubActionsWorkflow@v1", jsonPred.Parsed["buildType"])
			require.Len(t, res.GetSubjects(), 10)
		})
	}
}
