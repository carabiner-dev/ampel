// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"os"
	"testing"

	"github.com/carabiner-dev/collector/predicate"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

func TestEvaluateChainedSelector(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		code           string
		predicatePath  string
		expectedLength int
		expected       *intoto.ResourceDescriptor
		mustErr        bool
	}{
		{"slsa", "predicate.data.materials[0]", "testdata/slsa-v0.2.json", 1, &intoto.ResourceDescriptor{
			Uri:    "git+https://github.com/slsa-framework/slsa-verifier@refs/tags/v2.6.0",
			Digest: map[string]string{"sha1": "3714a2a4684014deb874a0e737dffa0ee02dd647", "gitCommit": "3714a2a4684014deb874a0e737dffa0ee02dd647"},
		}, false},
		{"string", "\"sha1:\"+predicate.data.materials[0].digest[\"sha1\"]", "testdata/slsa-v0.2.json", 1, &intoto.ResourceDescriptor{
			Digest: map[string]string{"sha1": "3714a2a4684014deb874a0e737dffa0ee02dd647"},
		}, false},
		{"bad-string", "\"bad string\"", "testdata/slsa-v0.2.json", 1, nil, true},
		{"bad-structure", "[1,2,3]", "testdata/slsa-v0.2.json", 1, nil, true},
	} {
		ev := &defaulCelEvaluator{}

		env, err := ev.CreateEnvironment(nil, nil)
		require.NoError(t, err)

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(tc.predicatePath)
			require.NoError(t, err)

			// Load the predicate from file
			pred, err := predicate.Parsers.Parse(data)
			require.NoError(t, err)

			// Compile the code
			ast, err := ev.CompileCode(env, tc.code)
			require.NoError(t, err)

			vars, err := ev.BuildSelectorVariables(&options.EvaluatorOptions{}, nil, nil, nil, nil, pred)
			require.NoError(t, err)

			res, err := ev.EvaluateChainedSelector(env, ast, vars)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Len(t, res, tc.expectedLength)
			require.Equal(t, tc.expected.GetUri(), res[0].GetUri())
			require.Equal(t, tc.expected.GetName(), res[0].GetName())
			require.Equal(t, tc.expected.GetDigest(), res[0].GetDigest())
		})
	}
}
