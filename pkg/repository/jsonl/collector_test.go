// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package jsonl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		srcData      string
		mustErr      bool
		expectedAtts int
	}{
		{"single", "testdata/single.jsonl", false, 1},
		{"bad", "testdata/bad.jsonl", true, 0},
		{"multiple", "testdata/multiple.jsonl", false, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			atts, err := parseFile(tc.srcData, nil)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, atts, tc.expectedAtts)
		})
	}
}

func TestReadAttestations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		files        []string
		mustErr      bool
		expectedAtts int
	}{
		{"single", []string{"testdata/single.jsonl"}, false, 1},
		{"bad", []string{"testdata/bad.jsonl"}, true, 0},
		{"multiple", []string{"testdata/multiple.jsonl", "testdata/single.jsonl"}, false, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{
				Options: Options{
					MaxParallel: 3,
					Paths:       []string{},
				},
			}
			atts, err := c.readAttestations(tc.files, nil)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, atts, tc.expectedAtts)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	t.Run("plain-new", func(t *testing.T) {
		t.Parallel()
		c, err := New()
		require.NoError(t, err)
		require.NotNil(t, c)
	})
	t.Run("with-path", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithPath("testdata/single.jsonl"))
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, []string{"testdata/single.jsonl"}, c.Options.Paths)
	})
	t.Run("with-maxp", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithMaxParallel(1000))
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, 1000, c.Options.MaxParallel)
	})
	t.Run("with-error", func(t *testing.T) {
		t.Parallel()
		_, err := New(WithPath("badfile"))
		require.Error(t, err)
	})
}
