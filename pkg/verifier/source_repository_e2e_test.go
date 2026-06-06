// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package verifier

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/envelope/bundle"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/stretchr/testify/require"
)

// TestSourceRepositoryURIEndToEnd exercises the whole chain against a real
// GitHub Actions keyless bundle: the collector captures the source repository
// URI (OID 1.3.6.1.4.1.57264.1.12) from the cert, and ampel's CheckIdentities
// matches it via source_repository_uri_match. Verification hits the sigstore
// trust root over TUF, so it needs network.
func TestSourceRepositoryURIEndToEnd(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	const repo = "https://github.com/sigstore/sigstore-js"

	exact := func(s string) *sapi.StringMatcher {
		return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: s}}
	}
	// A policy identity pinning the workflow issuer AND the origin repo.
	policy := func(srcRepo string) []*sapi.Identity {
		return []*sapi.Identity{{
			Sigstore: &sapi.IdentitySigstore{
				IssuerMatch:              exact(issuer),
				SourceRepositoryUriMatch: exact(srcRepo),
			},
		}}
	}

	envs, err := (&bundle.Parser{}).ParseFile("testdata/github-actions-bundle.json")
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	di := defaultIplementation{}
	check := func(ids []*sapi.Identity) bool {
		allow, _, _, err := di.CheckIdentities(
			t.Context(), &VerificationOptions{}, ids, []attestation.Envelope{envs[0]},
		)
		require.NoError(t, err)
		return allow
	}

	// Correct issuer + correct origin repo: the attestation is accepted.
	require.True(t, check(policy(repo)), "expected the real source repo to match")

	// Correct issuer + wrong origin repo: AND semantics fail closed.
	require.False(t, check(policy("https://github.com/evil/repo")), "wrong source repo must not match")
}
