// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulnreport

import (
	"errors"
	"fmt"

	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/trivy"
)

var ClassName = "vulnreport"

var PredicateTypes = []attestation.PredicateType{
	trivy.PredicateType,
}

// Transformer implements the normalizer from scanner to vulnv2
type Transformer struct{}

func (t *Transformer) Mutate(
	_ attestation.Subject, preds []attestation.Predicate,
) (attestation.Subject, []attestation.Predicate, error) {
	newPreds := []attestation.Predicate{}
	for _, original := range preds {
		//nolint:gocritic // This will take more types at some point
		switch original.GetType() {
		case trivy.PredicateType:
			newPred, err := t.TrivyToOSV(original)
			if err != nil {
				return nil, nil, fmt.Errorf("converting trivy predicate to OSV: %w", err)
			}
			newPreds = append(newPreds, newPred)
		}
	}
	return nil, newPreds, nil
}

//nolint:unused
func trivyToVulnsV2(original attestation.Predicate) (attestation.Predicate, error) {
	if original == nil {
		return nil, errors.New("original predicate undefined")
	}

	oParsed, ok := original.GetParsed().(*trivy.TrivyReport)
	if !ok {
		return nil, fmt.Errorf("unable to parse predicate payload as v02.Vulns")
	}

	newReport := &v02.Vulns{
		Scanner: &v02.Scanner{
			Uri:     "",
			Version: new(string),
			Db:      &v02.VulnDatabase{},
			Result:  []*v02.Result{},
		},
		Metadata: &v02.ScanMetadata{
			ScanStartedOn:  timestamppb.New(*oParsed.CreatedAt),
			ScanFinishedOn: timestamppb.New(*oParsed.CreatedAt),
		},
	}

	for _, result := range oParsed.Results {
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

			newReport.Scanner.Result = append(newReport.Scanner.Result, newResult)
		}
	}

	return &generic.Predicate{
		Type:   trivy.PredicateType,
		Parsed: newReport,
		Data:   []byte{},
	}, nil
}
