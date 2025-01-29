// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		options []ParseOption
		mustErr bool
	}{
		{"generic-json-fallback", []byte(`{"hello":"world", "isIt": true, "int": 32}`), nil, false},
		{"generic-json-err", []byte(`{"hello":"world", "isIt": true, "int": 32}`), []ParseOption{WithDefaulToJSON(false)}, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pred, err := Parsers.Parse(tc.data, tc.options...)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
		})
	}
}
