// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetValues(t *testing.T) {
	p1 := StringMapList([]string{"val1:b"})
	p2 := StringMapList([]string{"val1:a", "val2:2"})

	t.Parallel()
	for _, tt := range []struct {
		name      string
		providers []Provider
		keys      []string
		expect    map[string]any
		mustErr   bool
	}{
		{
			name:      "one",
			providers: []Provider{&p1},
			keys:      []string{"val1"},
			expect:    map[string]any{"val1": "b"},
		},
		{
			name:      "override",
			providers: []Provider{&p2, &p1},
			keys:      []string{"val1"},
			expect:    map[string]any{"val1": "a"},
		},
		{
			name:      "non-existent",
			providers: []Provider{&p2, &p1},
			keys:      []string{"valX"},
			expect:    map[string]any{},
		},
		{
			name:      "exists-only-in-second",
			providers: []Provider{&p1, &p2},
			keys:      []string{"val2"},
			expect:    map[string]any{"val2": "2"},
		},
		{
			name:      "one-from-each",
			providers: []Provider{&p1, &p2},
			keys:      []string{"val1", "val2"},
			expect:    map[string]any{"val1": "b", "val2": "2"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ret, err := GetValues(tt.providers, tt.keys)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expect, ret)
		})
	}
}
