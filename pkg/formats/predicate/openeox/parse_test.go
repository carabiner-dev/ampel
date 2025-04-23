// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package openeox

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		path         string
		data         []byte
		mustErr      bool
		checkError   error
		validatePred func(*testing.T, *generic.Predicate)
	}{
		{"normal", "testdata/sample-eox.json", nil, false, nil, func(t *testing.T, p *generic.Predicate) {
			t.Helper()
			require.NotNil(t, p.Parsed)
			require.NotNil(t, p.Data)
			require.NotEmpty(t, p.Data)
		}},
		{"other-json", "", []byte(`{"chido":1, "mas": "no", "soy": [1,2] }`), true, attestation.ErrNotCorrectFormat, nil},
		{"invalid-json", "", []byte(`"chido":1, "mas": "no", "soy": [1,2] }`), true, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New()
			if tc.path != "" {
				data, err := os.ReadFile(tc.path)
				require.NoError(t, err)
				tc.data = data
			}
			pred, err := p.Parse(tc.data)
			if tc.mustErr {
				require.Error(t, err)
				if tc.checkError != nil {
					require.ErrorIs(t, err, tc.checkError, "error must be %q", tc.checkError)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
		})
	}
}
