// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"
	"time"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/ampel/pkg/evaluator"
	"github.com/carabiner-dev/ampel/pkg/evaluator/class"
	eoptions "github.com/carabiner-dev/ampel/pkg/evaluator/options"
)

func TestEvaluateChain(t *testing.T) {
	t.Parallel()
	di := &defaultIplementation{}
	factory := evaluator.Factory{}

	def, err := factory.Get(&eoptions.Default, DefaultVerificationOptions.DefaultEvaluator)
	require.NoError(t, err)
	evaluators := map[class.Class]evaluator.Evaluator{
		"default": def,
		DefaultVerificationOptions.DefaultEvaluator: def,
	}

	defaultSubject := &gointoto.ResourceDescriptor{
		Name: "test",
		Digest: map[string]string{
			"sha256": "851074691728c479a4c83628de8310eaca792cc7",
		},
	}
	for _, tt := range []struct {
		name             string
		mustErr          bool
		expectedSubjects int
		subject          attestation.Subject
		attestationPaths []string
		chainLinks       []*papi.ChainLink
	}{
		{
			"self", false, 0, defaultSubject, []string{}, []*papi.ChainLink{},
		},
		{
			// test final multi
			"sbom", false, 170, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: `predicates[0].data.packages.filter(pkg, has(pkg.checksums) && size(pkg.checksums) > 0).map(pkg, { "name": has(pkg.name) ? pkg.name : "", "digest": pkg.checksums.map(checksum, { string(checksum.algorithm).lowerAscii(): dyn(checksum.checksumValue) })[0], 'uri': has(pkg.externalRefs) && size(pkg.externalRefs) > 0 ? dyn(pkg.externalRefs.filter(ref, ref.referenceType == 'purl')[0].referenceLocator) : dyn('')   })`,
						},
					},
				},
			},
		},
		// test intermediates not multi
		// test final single
		{
			// test final multi
			"multi", false, 2, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type: "https://spdx.dev/Document",
							// Selector: "predicates[0].data.packages",
							Selector: `["sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b", "sha256:0d413b00f20df75f452cdd3562edfa85983bde65917004be299902b734d24d8b"]`,
						},
					},
				},
			},
		},
		{
			// test final multi
			"no-matching-attestations", true, 0, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://cyclonedx.org/bom",
							Selector: `"sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b"`,
						},
					},
				},
			},
		},
		{
			"ensure-multi-intermediates-fail", true, 0, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: `["sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b", "sha256:0d413b00f20df75f452cdd3562edfa85983bde65917004be299902b734d24d8b"]`,
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b'",
						},
					},
				},
			},
		},
		{
			"ensure-final-can-be-multi", false, 2, defaultSubject,
			[]string{"testdata/wtf-frontend.spdx.json"},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: `["sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b", "sha256:0d413b00f20df75f452cdd3562edfa85983bde65917004be299902b734d24d8b"]`,
						},
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Load the attestations required by the test
			opts := &DefaultVerificationOptions
			opts.AttestationFiles = tt.attestationPaths
			attestations, err := di.ParseAttestations(t.Context(), opts)
			require.NoError(t, err)

			// Check if there is an evaluator foe the link's runtime
			for _, l := range tt.chainLinks {
				if runtime := l.GetPredicate().GetRuntime(); runtime != "" {
					if _, ok := evaluators[class.Class(runtime)]; ok {
						continue
					}
					ev, err := factory.Get(&eoptions.Default, class.Class(runtime))
					require.NoError(t, err)
					evaluators[class.Class(runtime)] = ev
				}
			}

			// should we test policyFail?
			subjects, chain, _, err := di.evaluateChain(
				t.Context(), &DefaultVerificationOptions, evaluators,
				nil, // the vollector agent should not be required
				tt.chainLinks,
				nil, // no context values in tests
				tt.subject, attestations, []*papi.Identity{}, "",
			)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			t.Logf("Got subjects:\n%+v", subjects)
			t.Logf("Got chain:\n%+v", chain)

			require.Len(t, subjects, tt.expectedSubjects)
		})
	}
}

func TestCheckPolicy(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		mustErr bool
		opts    *VerificationOptions
		policy  *papi.Policy
	}{
		{"normal", false, &DefaultVerificationOptions, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(1 * time.Hour))}}},
		{"expired", true, &DefaultVerificationOptions, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour))}}},
		{"nil-expiration", false, &DefaultVerificationOptions, &papi.Policy{Meta: &papi.Meta{Expiration: nil}}},
		{"expire-off-normal", false, &VerificationOptions{EnforceExpiration: false}, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(1 * time.Hour))}}},
		{"expire-off-expired", false, &VerificationOptions{EnforceExpiration: false}, &papi.Policy{Meta: &papi.Meta{Expiration: timestamppb.New(time.Now().Add(-1 * time.Hour))}}},
		{"expire-off-nil-expiration", false, &VerificationOptions{EnforceExpiration: false}, &papi.Policy{Meta: &papi.Meta{Expiration: nil}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			di := &defaultIplementation{}
			err := di.CheckPolicy(t.Context(), tt.opts, tt.policy)
			if tt.mustErr {
				require.Error(t, err)
				require.IsType(t, PolicyError{}, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
