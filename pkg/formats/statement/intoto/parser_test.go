// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package intoto

import (
	"os"
	"testing"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/json"
	v02 "github.com/carabiner-dev/ampel/pkg/formats/predicate/slsa/provenance/v02"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name              string
		data              []byte
		dataFile          string
		mustErr           bool
		validateStatement func(*testing.T, attestation.Statement)
	}{
		{"normal", nil, "testdata/sample.intoto.json", false, nil},
		{"non-intoto", []byte(`{"This": "is", "another": 1, "kind": ["of", "json"] }`), "", true, func(t *testing.T, s attestation.Statement) {
			t.Helper()
			pred := s.GetPredicate()
			genericPred, ok := pred.(*generic.Predicate)
			require.True(t, ok)
			parsed, ok := genericPred.GetParsed().(*v02.Provenance)
			require.Truef(t, ok, "%T", genericPred.GetParsed())
			require.Equal(t, "https://github.com/Attestations/GitHubActionsWorkflow@v1", parsed.BuildType)
			require.Len(t, s.GetSubjects(), 10)
		}},
		{"plain-json-pred", nil, "testdata/plain-json.json", false, func(t *testing.T, s attestation.Statement) {
			t.Helper()
			pred := s.GetPredicate()
			require.Equal(t, json.PredicateType, s.GetPredicateType())
			genericPred, ok := pred.(*generic.Predicate)
			require.True(t, ok)
			parsed, ok := genericPred.GetParsed().(json.DataMap)
			require.Truef(t, ok, "%T", genericPred.GetParsed())
			require.Equal(t, "am", parsed["I"])
			require.Len(t, s.GetSubjects(), 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := Parser{}
			data := tc.data
			if tc.dataFile != "" {
				var err error
				data, err = os.ReadFile(tc.dataFile)
				require.NoError(t, err)
			}
			res, err := p.Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.NotNil(t, res.GetPredicate())
			if tc.validateStatement != nil {
				tc.validateStatement(t, res)
			}
		})
	}
}
