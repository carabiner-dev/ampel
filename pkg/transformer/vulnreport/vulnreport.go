// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulnreport

import (
	"errors"
	"fmt"

	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/trivy"
	"github.com/puerco/ampel/pkg/formats/predicate/vulns"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ClassName = "vulnreport"

var PredicateTypes = []attestation.PredicateType{
	trivy.PredicateType,
}

// Transformer implements the normalizer from scanner to vulnv2
type Transformer struct {
}

func (t *Transformer) Mutate(preds []attestation.Predicate) ([]attestation.Predicate, error) {
	var newPreds = []attestation.Predicate{}
	for _, p := range preds {
		switch p.GetType() {
		case trivy.PredicateType:
			newPred, err := t.TrivyToOSV(p.(*trivy.Predicate))
			if err != nil {
				return nil, fmt.Errorf("converting trivy predicate to OSV: %w", err)
			}
			newPreds = append(newPreds, newPred)
		}
	}
	return newPreds, nil
}

func trivyToVulnsV2(original *trivy.Predicate) (*vulns.PredicateV2, error) {
	if original == nil {
		return nil, errors.New("original predicate undefined")
	}
	ret := &vulns.PredicateV2{
		Parsed: &v02.Vulns{
			Scanner: &v02.Scanner{
				Uri:      "",
				Version:  new(string),
				Database: &v02.VulnDatabase{},
				Result:   []*v02.Result{},
			},
			ScanMetadata: &v02.ScanMetadata{
				ScanStartedOn:  timestamppb.New(*original.Parsed.CreatedAt),
				ScanFinishedOn: timestamppb.New(*original.Parsed.CreatedAt),
			},
		},
	}

	if original.Parsed.Results == nil {
		return ret, nil
	}

	for _, result := range original.Parsed.Results {
		for _, vuln := range result.Vulnerabilities {
			newResult := &v02.Result{
				Id:          vuln.VulnerabilityID,
				Severity:    []*v02.Result_Severity{},
				Annotations: []*structpb.Struct{},
			}
			newResult.Severity = append(newResult.Severity, &v02.Result_Severity{
				Method: "",
				Score:  "",
			})

			ret.Parsed.Scanner.Result = append(ret.Parsed.Scanner.Result, newResult)
		}
	}

	return ret, nil
}
