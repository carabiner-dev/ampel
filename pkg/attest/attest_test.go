// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	gointoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// statementShape is a minimal in-toto Statement envelope used by the
// dispatch tests. Asserting on _type/predicateType/subject is enough
// to catch dispatch and writer wiring regressions without binding
// the test suite to any specific predicate schema.
type statementShape struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name,omitempty"`
		Digest map[string]string `json:"digest,omitempty"`
	} `json:"subject"`
}

func newSubject(digest string) *gointoto.ResourceDescriptor {
	return &gointoto.ResourceDescriptor{
		Digest: map[string]string{"sha256": digest},
	}
}

// newResultSet builds a minimal *papi.ResultSet carrying one passing
// Result per provided digest. The first digest also seeds the
// set-level Subject so VSA/SVR writers (which read set.GetSubject())
// have something to emit.
func newResultSet(t *testing.T, digests ...string) *papi.ResultSet {
	t.Helper()
	rs := &papi.ResultSet{
		DateStart: timestamppb.Now(),
		DateEnd:   timestamppb.Now(),
		Status:    papi.StatusPASS,
	}
	if len(digests) > 0 {
		rs.Subject = newSubject(digests[0])
	}
	for _, d := range digests {
		rs.Results = append(rs.Results, &papi.Result{
			Subject: newSubject(d),
			Status:  papi.StatusPASS,
		})
	}
	return rs
}

func TestAttestTo_FormatDispatch(t *testing.T) {
	cases := []struct {
		format       string
		wantPredType string
	}{
		{"ampel", "https://carabiner.dev/ampel/resultset/v0"},
		{"vsa", "https://slsa.dev/verification_summary/v1"},
		{"svr", "https://in-toto.io/attestation/svr/v0.1"},
	}
	rs := newResultSet(t, "deadbeef")
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := New().AttestTo(&buf, rs, WithFormat(tc.format)); err != nil {
				t.Fatalf("AttestTo: %v", err)
			}
			var stmt statementShape
			if err := json.Unmarshal(buf.Bytes(), &stmt); err != nil {
				t.Fatalf("unmarshaling output: %v\nbody: %s", err, buf.String())
			}
			if stmt.PredicateType != tc.wantPredType {
				t.Errorf("predicateType = %q, want %q", stmt.PredicateType, tc.wantPredType)
			}
		})
	}
}

func TestAttestTo_FormatDefault(t *testing.T) {
	const wantAmpel = "https://carabiner.dev/ampel/resultset/v0"
	rs := newResultSet(t, "deadbeef")
	cases := []struct {
		name string
		opts []FnOpt
	}{
		{"no option", nil},
		{"explicit empty", []FnOpt{WithFormat("")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := New().AttestTo(&buf, rs, tc.opts...); err != nil {
				t.Fatalf("AttestTo: %v", err)
			}
			var stmt statementShape
			if err := json.Unmarshal(buf.Bytes(), &stmt); err != nil {
				t.Fatalf("unmarshaling output: %v", err)
			}
			if stmt.PredicateType != wantAmpel {
				t.Errorf("predicateType = %q, want %q", stmt.PredicateType, wantAmpel)
			}
		})
	}
}

func TestAttestTo_UnknownFormat(t *testing.T) {
	rs := newResultSet(t, "deadbeef")
	err := New().AttestTo(&bytes.Buffer{}, rs, WithFormat("bogus"))
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error should mention the format name; got: %v", err)
	}
}

func TestAttestTo_PrettyPrint(t *testing.T) {
	rs := newResultSet(t, "deadbeef")

	var pretty bytes.Buffer
	if err := New().AttestTo(&pretty, rs); err != nil {
		t.Fatalf("default AttestTo: %v", err)
	}
	if !bytes.Contains(pretty.Bytes(), []byte("\n")) {
		t.Errorf("default output should be multi-line; got:\n%s", pretty.String())
	}

	var compact bytes.Buffer
	if err := New().AttestTo(&compact, rs, WithPrettyPrint(false)); err != nil {
		t.Fatalf("compact AttestTo: %v", err)
	}
	if bytes.Contains(compact.Bytes(), []byte("\n")) {
		t.Errorf("WithPrettyPrint(false) should produce single-line output; got:\n%s", compact.String())
	}
}

func TestAttestAmpel_SubjectDedup(t *testing.T) {
	// Two results sharing the same digest should yield one subject.
	rs := newResultSet(t, "deadbeef", "deadbeef")
	var buf bytes.Buffer
	if err := New().AttestTo(&buf, rs); err != nil {
		t.Fatalf("AttestTo: %v", err)
	}
	var stmt statementShape
	if err := json.Unmarshal(buf.Bytes(), &stmt); err != nil {
		t.Fatalf("unmarshaling output: %v", err)
	}
	if got := len(stmt.Subject); got != 1 {
		t.Errorf("subject count = %d, want 1 (dedup); subjects: %+v", got, stmt.Subject)
	}
}

func TestAttestVSA_ResultGroupNotSupported(t *testing.T) {
	grp := &papi.ResultGroup{Status: papi.StatusPASS}
	err := New().AttestTo(&bytes.Buffer{}, grp, WithFormat("vsa"))
	if err == nil || !strings.Contains(err.Error(), "not supported yet") {
		t.Errorf("want \"not supported yet\" error; got %v", err)
	}
}

func TestAttestSVR_ResultGroupNotSupported(t *testing.T) {
	grp := &papi.ResultGroup{Status: papi.StatusPASS}
	err := New().AttestTo(&bytes.Buffer{}, grp, WithFormat("svr"))
	if err == nil || !strings.Contains(err.Error(), "not supported yet") {
		t.Errorf("want \"not supported yet\" error; got %v", err)
	}
}

func TestStringifyDigests(t *testing.T) {
	cases := []struct {
		name   string
		digest map[string]string
		want   string
	}{
		{"empty", map[string]string{}, ""},
		{"single", map[string]string{"sha256": "deadbeef"}, "sha256:deadbeef"},
		{"sorted", map[string]string{"sha512": "ffff", "sha1": "1111"}, "sha1:1111/sha512:ffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stringifyDigests(&gointoto.ResourceDescriptor{Digest: tc.digest})
			if got != tc.want {
				t.Errorf("stringifyDigests = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStringifyDigests_OrderStability guards against accidental
// removal of the slices.Sort step: with multiple digest algorithms,
// map iteration order is randomized, so an unsorted output would
// flake across calls.
func TestStringifyDigests_OrderStability(t *testing.T) {
	sub := &gointoto.ResourceDescriptor{Digest: map[string]string{
		"sha256": "deadbeef", "sha1": "1111", "sha512": "ffff",
	}}
	first := stringifyDigests(sub)
	for i := range 10 {
		if got := stringifyDigests(sub); got != first {
			t.Errorf("iter %d: stringifyDigests = %q, want %q", i, got, first)
		}
	}
}

// newKeySigner returns a *signer.Signer wired to the key backend
// using a freshly generated keypair. Suitable for exercising the
// signed-output path without an OIDC popup or external dependency.
func newKeySigner(t *testing.T) *signer.Signer {
	t.Helper()
	priv, err := key.NewGenerator().GenerateKeyPair()
	if err != nil {
		t.Fatalf("generating signing key: %v", err)
	}
	s := signer.NewSigner()
	s.Options.Backend = options.BackendKey
	s.Options.Keys = []key.PrivateKeyProvider{priv}
	return s
}

// dsseEnvelope is the on-the-wire shape of a key-backend signed
// artifact, used to assert that the signed-path output is a DSSE
// envelope rather than a raw Statement.
type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// TestAttestTo_Signed_ConstructorSigner exercises the typical CLI
// path: signer is bound at New time and AttestTo emits a DSSE
// envelope (key backend) carrying the in-toto Statement as payload.
func TestAttestTo_Signed_ConstructorSigner(t *testing.T) {
	s := newKeySigner(t)
	rs := newResultSet(t, "deadbeef")

	var buf bytes.Buffer
	if err := New(WithSigner(s)).AttestTo(&buf, rs); err != nil {
		t.Fatalf("AttestTo: %v", err)
	}

	var env dsseEnvelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("output is not a DSSE envelope: %v\nbody: %s", err, buf.String())
	}
	if env.Payload == "" {
		t.Fatal("envelope payload is empty")
	}
	if len(env.Signatures) == 0 {
		t.Fatal("envelope has no signatures")
	}

	// The base64-decoded payload should be the in-toto Statement
	// carrying the ampel resultset predicateType.
	decoded, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var stmt statementShape
	if err := json.Unmarshal(decoded, &stmt); err != nil {
		t.Fatalf("payload is not a Statement: %v\npayload: %s", err, decoded)
	}
	if stmt.PredicateType != "https://carabiner.dev/ampel/resultset/v0" {
		t.Errorf("payload predicateType = %q, want ampel resultset", stmt.PredicateType)
	}
}

// TestAttestTo_Signed_PerCallOverride exercises the library-caller
// path: attester is constructed with no signer, but a per-call
// WithSigner enables signing for one AttestTo invocation.
func TestAttestTo_Signed_PerCallOverride(t *testing.T) {
	s := newKeySigner(t)
	rs := newResultSet(t, "deadbeef")

	a := New() // no constructor signer
	var buf bytes.Buffer
	if err := a.AttestTo(&buf, rs, WithSigner(s)); err != nil {
		t.Fatalf("AttestTo: %v", err)
	}
	var env dsseEnvelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("output is not a DSSE envelope: %v\nbody: %s", err, buf.String())
	}
	if env.Payload == "" || len(env.Signatures) == 0 {
		t.Errorf("envelope missing payload or signatures: %+v", env)
	}
}

// TestAttestTo_Signed_PerCallNilOverride confirms that passing
// WithSigner(nil) at call time disables signing even when a signer
// was bound at New time. Useful for callers that want to selectively
// emit unsigned attestations from a signing-default attester.
func TestAttestTo_Signed_PerCallNilOverride(t *testing.T) {
	s := newKeySigner(t)
	rs := newResultSet(t, "deadbeef")

	a := New(WithSigner(s))
	var buf bytes.Buffer
	if err := a.AttestTo(&buf, rs, WithSigner(nil)); err != nil {
		t.Fatalf("AttestTo: %v", err)
	}
	// Output is the raw in-toto Statement, not a DSSE envelope.
	var stmt statementShape
	if err := json.Unmarshal(buf.Bytes(), &stmt); err != nil {
		t.Fatalf("output should be a Statement: %v", err)
	}
	if stmt.PredicateType != "https://carabiner.dev/ampel/resultset/v0" {
		t.Errorf("predicateType = %q, want ampel resultset", stmt.PredicateType)
	}
	// Sanity: ensure no DSSE shape leaked through.
	var env dsseEnvelope
	if err := json.Unmarshal(buf.Bytes(), &env); err == nil && env.Payload != "" {
		t.Errorf("expected unsigned output; got DSSE-shaped payload field")
	}
}

func TestResultStringToSLSAResult(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{papi.StatusPASS, "PASSED"},
		{papi.StatusSOFTFAIL, "PASSED"},
		{papi.StatusFAIL, "FAILED"},
		{"", ""},
		{"weird", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := resultStringToSLSAResult(tc.in); got != tc.want {
				t.Errorf("resultStringToSLSAResult(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
