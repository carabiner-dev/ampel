// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulnreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/predicate/trivy"
	"github.com/carabiner-dev/collector/predicate/vulns"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// trivyScannerURI identifies the Trivy scanner in vulns/v0.2 Scanner.uri.
const trivyScannerURI = "https://trivy.dev"

var ClassName = "vulnreport"

var PredicateTypes = []attestation.PredicateType{
	trivy.PredicateType,
}

// Output formats the vulnreport transformer can emit.
const (
	OutputOSV        = "osv"
	OutputVulnReport = "vulnreport"
)

// Config is the user-facing configuration for the vulnreport transformer.
type Config struct {
	// Output selects the predicate format emitted by Mutate.
	// Defaults to "osv". "vulnreport" emits an in-toto vulns/v0.2 predicate.
	Output string `json:"output"`
}

func New() *Transformer {
	return &Transformer{}
}

// Transformer implements the normalizer from scanner to vulnv2
type Transformer struct {
	config Config
}

// Init parses the policy-supplied config and applies defaults.
func (t *Transformer) Init(raw *structpb.Struct) error {
	t.config = Config{Output: OutputOSV}
	if raw == nil {
		return nil
	}
	data, err := protojson.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshaling config struct: %w", err)
	}
	if err := json.Unmarshal(data, &t.config); err != nil {
		return fmt.Errorf("decoding vulnreport config: %w", err)
	}
	if t.config.Output == "" {
		t.config.Output = OutputOSV
	}
	switch t.config.Output {
	case OutputOSV, OutputVulnReport:
	default:
		return fmt.Errorf("unsupported output %q (want %q or %q)", t.config.Output, OutputOSV, OutputVulnReport)
	}
	return nil
}

func (t *Transformer) Mutate(
	_ attestation.Subject, preds []attestation.Predicate,
) (attestation.Subject, []attestation.Predicate, error) {
	newPreds := []attestation.Predicate{}
	for _, original := range preds {
		//nolint:gocritic // This will take more types at some point
		switch original.GetType() {
		case trivy.PredicateType:
			var (
				newPred attestation.Predicate
				err     error
			)
			switch t.config.Output {
			case OutputVulnReport:
				newPred, err = trivyToVulnsV2(original)
			default:
				newPred, err = t.TrivyToOSV(original)
			}
			if err != nil {
				return nil, nil, fmt.Errorf("converting trivy predicate to %s: %w", t.config.Output, err)
			}
			newPreds = append(newPreds, newPred)
		}
	}
	return nil, newPreds, nil
}

func trivyToVulnsV2(original attestation.Predicate) (attestation.Predicate, error) {
	if original == nil {
		return nil, errors.New("original predicate undefined")
	}

	oParsed, ok := original.GetParsed().(*trivy.TrivyReport)
	if !ok {
		return nil, fmt.Errorf("unable to parse predicate payload as trivy report")
	}

	scanTime := time.Now()
	if oParsed.CreatedAt != nil {
		scanTime = *oParsed.CreatedAt
	}

	newReport := &v02.Vulns{
		Scanner: &v02.Scanner{
			Uri:    trivyScannerURI,
			Result: []*v02.Result{},
		},
		Metadata: &v02.ScanMetadata{
			ScanStartedOn:  timestamppb.New(scanTime),
			ScanFinishedOn: timestamppb.New(scanTime),
		},
	}

	for _, result := range oParsed.Results {
		for _, vuln := range result.Vulnerabilities {
			newResult := &v02.Result{
				Id:          vuln.VulnerabilityID,
				Severity:    []*v02.Result_Severity{},
				Annotations: []*structpb.Struct{},
			}

			for _, cvss := range vuln.CVSS {
				newResult.Severity = append(newResult.Severity, &v02.Result_Severity{
					Method: "CVSS_V3",
					Score:  fmt.Sprintf("%.1f", cvss.V3Score),
				})
			}

			ann, err := structpb.NewStruct(map[string]any{
				"package":           vuln.PkgName,
				"installed_version": vuln.InstalledVersion,
				"fixed_version":     vuln.FixedVersion,
				"purl":              vuln.PkgIdentifier["PURL"],
				"severity":          vuln.Severity,
				"title":             vuln.Title,
			})
			if err != nil {
				return nil, fmt.Errorf("building result annotation: %w", err)
			}
			newResult.Annotations = append(newResult.Annotations, ann)

			newReport.Scanner.Result = append(newReport.Scanner.Result, newResult)
		}
	}

	data, err := protojson.Marshal(newReport)
	if err != nil {
		return nil, fmt.Errorf("marshaling vulns/v0.2 predicate: %w", err)
	}

	return &generic.Predicate{
		Type:   vulns.PredicateType,
		Parsed: newReport,
		Data:   data,
	}, nil
}
