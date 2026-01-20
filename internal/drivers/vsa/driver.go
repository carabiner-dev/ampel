// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/statement/intoto"
	papi "github.com/carabiner-dev/policy/api/v1"
	v1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// AMPEL verifier ID
	ampelId = "https://carabiner.dev/ampel@v1"

	// slsaVersion version used as base to compute the VSA
	slsaVersion = "1.1"

	// Recognized context keys for the VSA fields
	vsaContextResourceURIKey = "vsa.resourceUri"
)

func New() *Driver {
	return &Driver{}
}

type Driver struct{}

func renderAttestation(w io.Writer, subject attestation.Subject, att *v1.VerificationSummary) error {
	vsaJsonData, err := protojson.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling vsa: %w", err)
	}

	// Generate the generica predicate
	pred := &generic.Predicate{
		Type:   attestation.PredicateType("https://slsa.dev/verification_summary/v1"),
		Parsed: att,
		Data:   vsaJsonData,
	}

	// Add the intoto wrapper
	statement := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(&gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		}),
	)

	// Now serialize the attestation
	jsonData, err := json.Marshal(statement)
	if err != nil {
		return fmt.Errorf("serializing VSA: %w", err)
	}

	if _, err := w.Write(jsonData); err != nil {
		return fmt.Errorf("writing VSA data: %w", err)
	}
	return nil
}

// resultStringToSLSAResult translates from our policy evalt status strings to SLSA's
func resultStringToSLSAResult(status string) string {
	switch status {
	case papi.StatusPASS, papi.StatusSOFTFAIL:
		return "PASSED"
	case papi.StatusFAIL:
		return "FAILED"
	default:
		return ""
	}
}

// RenderResultSet renders a results set in a VSA.
//
// We map the result of the VSA (VerificationResult) to the PolicySet
// assesment result. The SLSA level captured in the the VerifiedLevels
// field is transferred from the common controls.
//
// Dependency levels are computed by extracting the results of policies
// chained to a different subject. Those policies are expected to have
// their own controls section, defining the SLSA level they check.
func (d *Driver) RenderResultSet(w io.Writer, set *papi.ResultSet) error {
	vsaData := &v1.VerificationSummary{
		Verifier: &v1.VerificationSummary_Verifier{
			Id: ampelId,
		},
		TimeVerified: set.GetDateEnd(),
		// We set the resource URI here to the resource URI of the verified subject
		// but if the policyset common context defines one, we'll override it later.
		ResourceUri: set.GetSubject().GetUri(),
		Policy: &v1.VerificationSummary_Policy{
			Uri:    set.GetMeta().GetOrigin().GetUri(),
			Digest: set.GetMeta().GetOrigin().GetDigest(),
		},
		InputAttestations:  []*v1.VerificationSummary_InputAttestation{},
		VerificationResult: resultStringToSLSAResult(set.GetStatus()),
		VerifiedLevels:     []string{},
		DependencyLevels:   nil,
	}

	inputs := []attestation.Subject{}
	depLevels := map[string]uint64{}

	// Check if the policyset defined a resourceURI for the VSA and replace the
	// value we got from the subject resource locator.
	if setContext := set.GetCommon().GetContext(); setContext != nil {
		if s, ok := setContext.AsMap()[vsaContextResourceURIKey].(string); ok && s != "" {
			vsaData.ResourceUri = s
		}
	}

	var verifiedSomeSlsa bool
	for _, a := range set.Results {
		for _, er := range a.EvalResults {
			for _, stRef := range er.GetStatements() {
				if !hasSubject(inputs, stRef.GetAttestation()) {
					inputs = append(inputs, stRef.GetAttestation())
				}
			}
		}

		// Collect any SLSA levels into the dep count
		if a.GetStatus() != papi.StatusPASS {
			continue
		}
		for _, ctl := range a.GetMeta().GetControls() {
			// Compute the label from the control
			if ctl.Id == "" {
				continue
			}
			label := ctl.Label()
			label = strings.ReplaceAll(label, "-", "_")
			if !strings.HasPrefix(label, "SLSA_") {
				continue
			}

			verifiedSomeSlsa = true

			// Here, we add the level to the verified levels when the result
			// subject matches the policyset subject. If not, then we assume the
			// policyset was chained to verify dependencies.
			if attestation.SubjectsMatch(set.GetSubject(), a.GetSubject()) {
				if !slices.Contains(vsaData.VerifiedLevels, label) {
					vsaData.VerifiedLevels = append(vsaData.VerifiedLevels, label)
				}
			} else {
				depLevels[label]++
			}
		}
	}
	if len(depLevels) > 0 {
		vsaData.DependencyLevels = depLevels
	}

	vsaData.InputAttestations = subjectsToSummaryInputs(inputs)
	if verifiedSomeSlsa {
		vsaData.SlsaVersion = slsaVersion
	}
	return renderAttestation(w, set.GetSubject(), vsaData)
}

func (d *Driver) RenderResultGroup(w io.Writer, result *papi.ResultGroup) error {
	return errors.New("rendering result groups as VSAs is not supported yet")
}

// RenderResult renders a policy evaluation result into a VSA
func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	vsaData := &v1.VerificationSummary{
		Verifier: &v1.VerificationSummary_Verifier{
			Id: ampelId,
		},
		TimeVerified: result.GetDateEnd(),
		// We fix the resource URI here to the resource URI of the verification
		// subject, but if the policy context defines one, we'll override it.
		ResourceUri: result.GetSubject().GetUri(),
		Policy: &v1.VerificationSummary_Policy{
			Uri:    result.GetMeta().GetOrigin().GetUri(),
			Digest: result.GetMeta().GetOrigin().GetDigest(),
		},
		// Populated later
		InputAttestations:  []*v1.VerificationSummary_InputAttestation{},
		VerificationResult: resultStringToSLSAResult(result.GetStatus()),
		VerifiedLevels:     []string{},
		DependencyLevels:   nil,
	}

	if resContext := result.GetContext(); resContext != nil {
		if v, ok := resContext.AsMap()[vsaContextResourceURIKey]; ok && v != nil {
			if s, ok2 := v.(string); ok2 && s != "" {
				vsaData.ResourceUri = s
			}
		}
	}

	var verifiedSomeSlsa bool
	// Add the verified level if its a slsa control
	for _, ctl := range result.GetMeta().GetControls() {
		label := strings.ReplaceAll(ctl.Label(), "-", "_")
		if !strings.HasPrefix(label, "SLSA_") {
			continue
		}
		verifiedSomeSlsa = true
		vsaData.VerifiedLevels = append(vsaData.VerifiedLevels, label)
	}

	// Add the input attestations recorded in the result
	inputs := []attestation.Subject{}
	for _, er := range result.EvalResults {
		// Add the statements to the collection
		for _, stRef := range er.GetStatements() {
			if !hasSubject(inputs, stRef.GetAttestation()) {
				inputs = append(inputs, stRef.GetAttestation())
			}
		}
	}
	vsaData.InputAttestations = subjectsToSummaryInputs(inputs)
	if verifiedSomeSlsa {
		vsaData.SlsaVersion = slsaVersion
	}
	return renderAttestation(w, result.GetSubject(), vsaData)
}

func subjectsToSummaryInputs(inputs []attestation.Subject) []*v1.VerificationSummary_InputAttestation {
	ret := make([]*v1.VerificationSummary_InputAttestation, 0, len(inputs))
	for _, s := range inputs {
		i := &v1.VerificationSummary_InputAttestation{
			Uri:    s.GetUri(),
			Digest: s.GetDigest(),
		}
		ret = append(ret, i)
	}
	if len(ret) == 0 {
		return nil
	}
	return ret
}

func hasSubject(haystack []attestation.Subject, needle attestation.Subject) bool {
	for _, sut := range haystack {
		if attestation.SubjectsMatch(sut, needle) {
			return true
		}
	}
	return false
}
