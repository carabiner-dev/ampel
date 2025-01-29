// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package intoto

import (
	"fmt"
	"os"
	"testing"

	"github.com/puerco/ampel/pkg/formats/predicate/generic"
	v02 "github.com/puerco/ampel/pkg/formats/predicate/slsa/provenance/v02"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		dataFile string
		mustErr  bool
	}{
		{"normal", "testdata/sample.intoto.json", false},
		// TODO(puerco): Add plain json predicate
		// TODO(puerco): Add other json (non-intoto)
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
			genericPred, ok := pred.(*generic.Predicate)
			require.True(t, ok)
			parsed, ok := genericPred.GetParsed().(*v02.Provenance)
			require.Truef(t, ok, fmt.Sprintf("%T", genericPred.GetParsed()))
			require.Equal(t, "https://github.com/Attestations/GitHubActionsWorkflow@v1", parsed.BuildType)
			require.Len(t, res.GetSubjects(), 10)
		})
	}
}
