// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filters

import (
	"testing"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/envelope/bare"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestSubjectHashMatcher(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		hashsets []map[string]string
		getSUT   func(*testing.T) attestation.Envelope
		expect   bool
	}{
		{
			"single-hash",
			[]map[string]string{
				{"sha1": "e67eddfacbd2e8eefec191410bcce469079bc186"},
			},
			func(t *testing.T) attestation.Envelope {
				t.Helper()
				statement := intoto.NewStatement()
				statement.AddSubject(&gointoto.ResourceDescriptor{
					Digest: map[string]string{
						"sha1": "e67eddfacbd2e8eefec191410bcce469079bc186",
					},
				})
				env := &bare.Envelope{Statement: statement}
				return env
			},
			true,
		},
		{
			"single-hash-matches-two-hashes",
			[]map[string]string{
				{"sha1": "e67eddfacbd2e8eefec191410bcce469079bc186"},
			},
			func(t *testing.T) attestation.Envelope {
				t.Helper()
				statement := intoto.NewStatement()
				statement.AddSubject(&gointoto.ResourceDescriptor{
					Digest: map[string]string{
						"sha1":   "e67eddfacbd2e8eefec191410bcce469079bc186",
						"sha256": "8c61b87a505474105dd251fe05ab43c8278675f4667bde245ad89992b926f8f9",
					},
				})
				env := &bare.Envelope{Statement: statement}
				return env
			},
			true,
		},
		{
			"two-hash-matches-two-hashes",
			[]map[string]string{
				{
					"sha1":   "e67eddfacbd2e8eefec191410bcce469079bc186",
					"sha256": "8c61b87a505474105dd251fe05ab43c8278675f4667bde245ad89992b926f8f9",
				},
			},
			func(t *testing.T) attestation.Envelope {
				t.Helper()
				statement := intoto.NewStatement()
				statement.AddSubject(&gointoto.ResourceDescriptor{
					Digest: map[string]string{
						"sha1":   "e67eddfacbd2e8eefec191410bcce469079bc186",
						"sha256": "8c61b87a505474105dd251fe05ab43c8278675f4667bde245ad89992b926f8f9",
					},
				})
				env := &bare.Envelope{Statement: statement}
				return env
			},
			true,
		},
		{
			"two-hash-mismatch-two-hashes",
			[]map[string]string{
				{
					"sha256": "uiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiuiu",
					"sha1":   "Se67eddfacbd2e8eefec191410bcce469079bc186",
				},
			},
			func(t *testing.T) attestation.Envelope {
				t.Helper()
				statement := intoto.NewStatement()
				statement.AddSubject(&gointoto.ResourceDescriptor{
					Digest: map[string]string{
						"sha1":   "Se67eddfacbd2e8eefec191410bcce469079bc186",
						"sha256": "8c61b87a505474105dd251fe05ab43c8278675f4667bde245ad89992b926f8f9",
					},
				})
				env := &bare.Envelope{Statement: statement}
				return env
			},
			false,
		},
		{
			"three-hashes-matches-two-hashes",
			[]map[string]string{
				{
					"sha1":   "e67eddfacbd2e8eefec191410bcce469079bc186",
					"sha256": "8c61b87a505474105dd251fe05ab43c8278675f4667bde245ad89992b926f8f9",
					"sha512": "5f09223c36eb76fb9beb88372f8a379bc7539de6bc5425e06083550edeb874cb8e7d4805c4f8c5a6218cdff2fd8d2eb56a8059db5b63d012facab9e069f43453",
				},
			},
			func(t *testing.T) attestation.Envelope {
				t.Helper()
				statement := intoto.NewStatement()
				statement.AddSubject(&gointoto.ResourceDescriptor{
					Digest: map[string]string{
						"sha1":   "e67eddfacbd2e8eefec191410bcce469079bc186",
						"sha256": "8c61b87a505474105dd251fe05ab43c8278675f4667bde245ad89992b926f8f9",
					},
				})
				env := &bare.Envelope{Statement: statement}
				return env
			},
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matcher := SubjectHashMatcher{
				HashSets: tc.hashsets,
			}

			require.Equal(t, tc.expect, matcher.Match(tc.getSUT(t)))
		})
	}
}
