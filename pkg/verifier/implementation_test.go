// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"
	"time"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/statement/intoto"
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
			[]string{
				"testdata/wtf-frontend.spdx.json",
				"testdata/link1.json",
				"testdata/link2.json",
			},
			[]*papi.ChainLink{
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://spdx.dev/Document",
							Selector: "'sha1:856314ba21181a746186c24f1647d06e45048964'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://example.com/",
							Selector: "'sha1:93836eee21527f010b77faa3379ccba2f3dbc1b3'",
						},
					},
				},
				{
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://example.com/",
							Selector: `["sha256:cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b", "sha256:0d413b00f20df75f452cdd3562edfa85983bde65917004be299902b734d24d8b"]`,
						},
					},
				},
			},
		},
		{
			// Test that sha1: subject prefix works with gitCommit: attestation digest type
			// This is the exact bug reported in the GitHub issue: https://github.com/carabiner-dev/ampel/issues/175
			// Subject with sha1: should match attestations with gitCommit: digest
			"gitCommit-sha1-matching-bug-fix", false, 1, &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					// User specifies subject with sha1: prefix (as with ampel verify --subject=sha1:...)
					"sha1": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			[]string{
				// Attestation file has subject with gitCommit digest type
				"testdata/gitcommit-attestation.json",
			},
			[]*papi.ChainLink{
				{
					// Chain selector returns a simple subject
					// The key test is that the initial subject (sha1:...) matches
					// the attestation (gitCommit:...) to trigger this selector
					Source: &papi.ChainLink_Predicate{
						Predicate: &papi.ChainedPredicate{
							Type:     "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft",
							Selector: `[{ "name": "test-repo-output" }]`,
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
			attestations, err := di.ParseAttestations(t.Context(), opts, tt.subject)
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
				require.IsType(t, PolicyError{}, err) //nolint:testifylint // Checking for type, not value
				return
			}
			require.NoError(t, err)
		})
	}
}

type fakeEnvelope struct {
	ver attestation.Verification
}

func (fe *fakeEnvelope) GetStatement() attestation.Statement       { return &intoto.Statement{} }
func (fe *fakeEnvelope) GetPredicate() attestation.Predicate       { return nil }
func (fe *fakeEnvelope) GetSignatures() []attestation.Signature    { return nil }
func (fe *fakeEnvelope) GetCertificate() attestation.Certificate   { return nil }
func (fe *fakeEnvelope) GetVerification() attestation.Verification { return fe.ver }
func (fe *fakeEnvelope) Verify(...any) error                       { return nil }

var _ attestation.Envelope = &fakeEnvelope{}

func TestNormalizeSubjectDigests(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name           string
		subject        attestation.Subject
		enableHack     bool
		expectedDigest map[string]string
	}{
		{
			name: "gitCommit-to-sha1-hack-enabled",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "sha1-to-gitCommit-hack-enabled",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"sha1": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "gitCommit-to-sha1-hack-disabled",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: false,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "both-present-no-normalization",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
					"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
			},
		},
		{
			name: "invalid-length-sha1-no-normalization",
			subject: &gointoto.ResourceDescriptor{
				Name: "commit",
				Digest: map[string]string{
					"sha1": "tooshort",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"sha1": "tooshort",
			},
		},
		{
			name: "sha256-no-normalization",
			subject: &gointoto.ResourceDescriptor{
				Name: "artifact",
				Digest: map[string]string{
					"sha256": "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"sha256": "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
			},
		},
		{
			name: "multiple-digests-with-gitCommit",
			subject: &gointoto.ResourceDescriptor{
				Name: "multi",
				Digest: map[string]string{
					"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
					"sha256":    "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
				},
			},
			enableHack: true,
			expectedDigest: map[string]string{
				"gitCommit": "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha1":      "93ef1a1a5a955e23cbe0ffacc4db8da11b0cc2e6",
				"sha256":    "851074691728c479a4c83628de8310eaca792cc7851074691728c479a4c83628",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := normalizeSubjectDigests(tt.subject, tt.enableHack)
			require.Equal(t, tt.expectedDigest, result.GetDigest())
		})
	}
}

func TestCheckIdentities(t *testing.T) {
	t.Parallel()
	idSigstore := &papi.Identity{
		Id: "abc",
		Sigstore: &papi.IdentitySigstore{
			Issuer:   "https://example.com",
			Identity: "joe@example.com",
		},
	}
	idSigstoreOther := &papi.Identity{
		Id: "abc",
		Sigstore: &papi.IdentitySigstore{
			Issuer:   "https://nonexistent.com",
			Identity: "mark@hami-ll.com",
		},
	}
	di := defaultIplementation{}
	for _, tt := range []struct {
		name             string
		opts             VerificationOptions
		policyIdentities []*papi.Identity
		envelopes        []attestation.Envelope
		mustErr          bool
		mustAllow        bool
	}{
		{"no-allowedIdentities-defined", DefaultVerificationOptions, []*papi.Identity{}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &papi.Verification{Signature: &papi.SignatureVerification{Verified: true, Identities: []*papi.Identity{idSigstore}}},
			},
		}, false, true},
		{"no-matching-identities-opts", VerificationOptions{IdentityStrings: []string{idSigstore.Slug()}}, []*papi.Identity{}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &papi.Verification{Signature: &papi.SignatureVerification{Verified: true, Identities: []*papi.Identity{idSigstoreOther}}},
			},
		}, false, false},
		{"no-matching-identities-policy", VerificationOptions{IdentityStrings: []string{}}, []*papi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &papi.Verification{Signature: &papi.SignatureVerification{Verified: true, Identities: []*papi.Identity{idSigstoreOther}}},
			},
		}, false, false},
		{"ids-in-opts", VerificationOptions{IdentityStrings: []string{idSigstore.Slug()}}, []*papi.Identity{}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &papi.Verification{Signature: &papi.SignatureVerification{Verified: true, Identities: []*papi.Identity{idSigstore}}},
			},
		}, false, true},
		{"ids-in-policy", VerificationOptions{IdentityStrings: []string{}}, []*papi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &papi.Verification{
					Signature: &papi.SignatureVerification{Verified: true, Identities: []*papi.Identity{idSigstore}},
				},
			},
		}, false, true},
		{"ids-in-policy-over-opts-pass", VerificationOptions{IdentityStrings: []string{idSigstoreOther.Slug()}}, []*papi.Identity{idSigstore}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &papi.Verification{
					Signature: &papi.SignatureVerification{Verified: true, Identities: []*papi.Identity{idSigstore}},
				},
			},
		}, false, true},
		{"ids-in-policy-over-opts-fail", VerificationOptions{IdentityStrings: []string{idSigstore.Slug()}}, []*papi.Identity{idSigstoreOther}, []attestation.Envelope{
			&fakeEnvelope{
				ver: &papi.Verification{
					Signature: &papi.SignatureVerification{Verified: true, Identities: []*papi.Identity{idSigstore}},
				},
			},
		}, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// allow, ids, errs, err
			allow, _, _, err := di.CheckIdentities(
				t.Context(), &tt.opts, tt.policyIdentities, tt.envelopes,
			)

			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.mustAllow, allow)
		})
	}
}
