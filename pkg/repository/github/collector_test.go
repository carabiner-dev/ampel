// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"testing"

	"github.com/carabiner-dev/github"
	"github.com/stretchr/testify/require"
)

func TestFetchFromUrl(t *testing.T) {
	for _, tc := range []struct {
		name         string
		srcData      string
		synterr      error
		expectedAtts int
	}{
		{"normal", "testdata/output.json", nil, 2},
		{"err", "", errors.New("bad boi"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create the mocked client
			client, err := github.NewClient(
				github.WithCaller(
					&github.FileCaller{
						SourcePath: tc.srcData,
						Error:      tc.synterr,
					},
				),
				github.WithEnsureToken(false),
			)
			require.NoError(t, err)

			collector := &Collector{
				Options: Options{},
				client:  client,
			}

			// Call the fetch
			res, _, err := collector.fetchFromUrl(
				context.Background(),
				"users/carabiner-dev/attestations/sha256:2775bba8b2170bef2f91b79d4f179fd87724ffee32b4a20b8304856fd3bf4b8f",
			)
			if tc.synterr != nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, res, tc.expectedAtts)
			//fmt.Printf("%+v", res)
			//t.Fail()
		})
	}

}
