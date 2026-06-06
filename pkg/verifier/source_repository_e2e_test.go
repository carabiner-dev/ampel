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

// TestSourceRepositoryURIDynamicEndToEnd exercises the dynamic path: the
// published policy bakes in the signer issuer and leaves the origin repo as a
// {{ .Context.x }} template; the verifier supplies the repo at runtime (as
// -x source_repo=... would). resolvePolicyIdentities fills the matcher BEFORE
// CheckIdentities, so the constraint stays AND-ed inside the identity and fails
// closed.
func TestSourceRepositoryURIDynamicEndToEnd(t *testing.T) {
	const issuer = "https://token.actions.githubusercontent.com"
	const repo = "https://github.com/sigstore/sigstore-js"

	exact := func(s string) *sapi.StringMatcher {
		return &sapi.StringMatcher{Kind: &sapi.StringMatcher_Exact{Exact: s}}
	}
	// The published policy: issuer baked in, repo supplied via context.
	published := func() []*sapi.Identity {
		return []*sapi.Identity{{
			Sigstore: &sapi.IdentitySigstore{
				IssuerMatch:              exact(issuer),
				SourceRepositoryUriMatch: exact("{{ .Context.source_repo }}"),
			},
		}}
	}

	envs, err := (&bundle.Parser{}).ParseFile("testdata/github-actions-bundle.json")
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	di := defaultIplementation{}
	checkWith := func(ctxVals map[string]any) (bool, error) {
		resolved, err := resolvePolicyIdentities(published(), ctxVals)
		if err != nil {
			return false, err
		}
		allow, _, _, err := di.CheckIdentities(
			t.Context(), &VerificationOptions{}, resolved, []attestation.Envelope{envs[0]},
		)
		require.NoError(t, err)
		return allow, nil
	}

	// Verifier supplies the correct repo -> template resolves -> accepted.
	allow, err := checkWith(map[string]any{"source_repo": repo})
	require.NoError(t, err)
	require.True(t, allow, "verifier-supplied correct repo must match")

	// Verifier supplies a wrong repo -> fails closed (AND with the baked issuer).
	allow, err = checkWith(map[string]any{"source_repo": "https://github.com/evil/repo"})
	require.NoError(t, err)
	require.False(t, allow, "verifier-supplied wrong repo must not match")

	// Verifier supplies nothing -> resolution errors (fail closed), not match-anything.
	_, err = checkWith(map[string]any{})
	require.Error(t, err, "missing required context value must error, not silently pass")

	// The shared policy proto is never mutated: resolving a captured identity
	// leaves the original template in place (clone, don't mutate).
	original := published()
	_, err = resolvePolicyIdentities(original, map[string]any{"source_repo": repo})
	require.NoError(t, err)
	require.Equal(t,
		"{{ .Context.source_repo }}",
		original[0].GetSigstore().GetSourceRepositoryUriMatch().GetExact(),
		"resolvePolicyIdentities must not mutate the shared policy identity",
	)
}
