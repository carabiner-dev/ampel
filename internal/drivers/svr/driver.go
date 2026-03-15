// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package svr

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
	svr "github.com/in-toto/attestation/go/predicates/svr/v01"
	gointoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	ampelId       = "https://carabiner.dev/ampel@v1"
	predicateType = "https://in-toto.io/attestation/svr/v0.1"
)

func New() *Driver {
	return &Driver{}
}

type Driver struct{}

func renderAttestation(w io.Writer, subject attestation.Subject, att *svr.SimpleVerificationResult) error {
	svrJsonData, err := protojson.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshaling svr: %w", err)
	}

	// The anypb.Any wrapper injects a @type field into the policy block
	// that we don't want in the SVR output. Strip it.
	var raw map[string]any
	if err := json.Unmarshal(svrJsonData, &raw); err != nil {
		return fmt.Errorf("unmarshaling svr json: %w", err)
	}
	if verifier, ok := raw["verifier"].(map[string]any); ok {
		if policy, ok := verifier["policy"].(map[string]any); ok {
			delete(policy, "@type")
		}
	}
	svrJsonData, err = json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("re-marshaling svr json: %w", err)
	}

	pred := &generic.Predicate{
		Type:   attestation.PredicateType(predicateType),
		Parsed: att,
		Data:   svrJsonData,
	}

	statement := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(&gointoto.ResourceDescriptor{
			Name:   subject.GetName(),
			Uri:    subject.GetUri(),
			Digest: subject.GetDigest(),
		}),
	)

	jsonData, err := json.Marshal(statement)
	if err != nil {
		return fmt.Errorf("serializing SVR: %w", err)
	}

	if _, err := w.Write(jsonData); err != nil {
		return fmt.Errorf("writing SVR data: %w", err)
	}
	return nil
}

func policyResourceDescriptor(origin attestation.Subject) (*anypb.Any, error) {
	rd := &gointoto.ResourceDescriptor{
		Uri:    origin.GetUri(),
		Digest: origin.GetDigest(),
	}
	return anypb.New(rd)
}

// RenderResultSet renders a result set as an SVR attestation.
func (d *Driver) RenderResultSet(w io.Writer, set *papi.ResultSet) error {
	policyAny, err := policyResourceDescriptor(set.GetMeta().GetOrigin())
	if err != nil {
		return fmt.Errorf("wrapping policy descriptor: %w", err)
	}

	svrData := &svr.SimpleVerificationResult{
		Verifier: &svr.SimpleVerificationResult_Verifier{
			Id:     ampelId,
			Policy: policyAny,
		},
		TimeCreated: set.GetDateEnd(),
		Properties:  []string{},
	}

	for _, a := range set.Results {
		if a.GetStatus() != papi.StatusPASS {
			continue
		}
		for _, ctl := range a.GetMeta().GetControls() {
			if ctl.Id == "" {
				continue
			}
			label := strings.ReplaceAll(ctl.Label(), "-", "_")
			if !slices.Contains(svrData.Properties, label) {
				svrData.Properties = append(svrData.Properties, label)
			}
		}
	}

	return renderAttestation(w, set.GetSubject(), svrData)
}

// RenderResultGroup renders a result group as an SVR attestation.
func (d *Driver) RenderResultGroup(_ io.Writer, _ *papi.ResultGroup) error {
	return errors.New("rendering result groups as SVRs is not supported yet")
}

// RenderResult renders a single policy evaluation result as an SVR attestation.
func (d *Driver) RenderResult(w io.Writer, result *papi.Result) error {
	policyAny, err := policyResourceDescriptor(result.GetMeta().GetOrigin())
	if err != nil {
		return fmt.Errorf("wrapping policy descriptor: %w", err)
	}

	svrData := &svr.SimpleVerificationResult{
		Verifier: &svr.SimpleVerificationResult_Verifier{
			Id:     ampelId,
			Policy: policyAny,
		},
		TimeCreated: result.GetDateEnd(),
		Properties:  []string{},
	}

	for _, ctl := range result.GetMeta().GetControls() {
		if ctl.Id == "" {
			continue
		}
		label := strings.ReplaceAll(ctl.Label(), "-", "_")
		if !slices.Contains(svrData.Properties, label) {
			svrData.Properties = append(svrData.Properties, label)
		}
	}

	return renderAttestation(w, result.GetSubject(), svrData)
}
