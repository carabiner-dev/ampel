// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"errors"
	"os"
	"testing"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	// the protobom parser is disabled for now
	t.Skip()
	for _, tc := range []struct {
		name        string
		file        string
		mustErr     bool
		badFormat   bool
		expectNodes int
		expectRoot  int
	}{
		{"spdx", "testdata/spdx.json", false, false, 40, 1},
		{"other-json", "testdata/other.json", true, true, 0, 0},
		{"invalid-json", "testdata/invalid-json.json", true, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Parser{}
			data, err := os.ReadFile(tc.file)
			require.NoError(t, err)
			pred, err := p.Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				if tc.badFormat {
					require.True(t, errors.Is(err, attestation.ErrNotCorrectFormat))
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
			protopred, ok := pred.(*generic.Predicate)
			require.True(t, ok)
			require.True(t, len(protopred.Data) > 0)
			require.Equal(t, tc.expectRoot, len(protopred.Parsed.(*sbom.Document).NodeList.RootElements))
			require.Equal(t, tc.expectNodes, len(protopred.Parsed.(*sbom.Document).NodeList.Nodes))
		})
	}
}
