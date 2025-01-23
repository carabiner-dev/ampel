package vulnreport

import (
	"errors"
	"fmt"
	"time"

	posv "github.com/puerco/ampel/pkg/formats/predicate/osv"
	"github.com/puerco/ampel/pkg/formats/predicate/trivy"
	"github.com/puerco/ampel/pkg/osv"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// trivyToOSV converts a trivy v2 output to an OSV feed
func (t *Transformer) TrivyToOSV(original *trivy.Predicate) (*posv.Predicate, error) {
	if original == nil {
		return nil, errors.New("original predicate undefined")
	}

	createdat := time.Now()
	if original.Parsed.CreatedAt != nil {
		createdat = *original.Parsed.CreatedAt
	}

	ret := &posv.Predicate{
		Parsed: &osv.Predicate{
			Date:    timestamppb.New(createdat),
			Records: []*osv.Record{},
		},
	}

	for _, result := range original.Parsed.Results {
		for _, vuln := range result.Vulnerabilities {
			rec := &osv.Record{
				SchemaVersion: osv.Version,
				Id:            vuln.VulnerabilityID,
				Aliases:       []string{},
				Related:       []string{},
				Summary:       vuln.Title,
				Details:       vuln.Description,
				Severity:      []*osv.Severity{},
				Affected: []*osv.Affected{
					{
						Package: &osv.Package{
							Name: vuln.PkgName,
						},
						Severity:          []*osv.Severity{},
						Ranges:            []*osv.Range{},
						Versions:          []string{},
						EcosystemSpecific: &structpb.Struct{},
						DatabaseSpecific:  &structpb.Struct{},
					},
				},
				References: []*osv.Reference{},
				Credits:    []*osv.Credit{},
			}

			if vuln.PublishedDate != nil {
				rec.Published = timestamppb.New(*vuln.PublishedDate)
			}

			if vuln.LastModifiedDate != nil {
				rec.Modified = timestamppb.New(*vuln.LastModifiedDate)
			}

			if v, ok := vuln.PkgIdentifier["PURL"]; ok {
				// TODO(puerco): Compute ecosystem from purl
				// Ecosystem: "",
				rec.Affected[0].Package.Purl = v
			}

			for _, r := range vuln.References {
				rec.References = append(rec.References, &osv.Reference{
					Type: "URL",
					Url:  r,
				})
			}

			// Add the severities
			for _, cvss := range vuln.CVSS {
				rec.Severity = append(rec.Severity, &osv.Severity{
					Type:  "CVSS_V3",
					Score: fmt.Sprintf("%.1f", cvss.V3Score),
				})
			}

			// Compute a range with the versions
			rec.Affected[0].Ranges = append(rec.Affected[0].Ranges, &osv.Range{
				Type: "SEMVER",
				Events: []*osv.Range_Event{
					{
						Introduced: vuln.InstalledVersion,
						Fixed:      vuln.FixedVersion,
					},
				},
			})

			// Add the ecosystem specific data with our findings
			dbs, err := structpb.NewStruct(map[string]any{
				"ampel": map[string]any{
					"severity": vuln.Severity,
					"CWE":      vuln.CweIDs,
					"KEV":      "",
				},
			})
			if err != nil {
				return nil, fmt.Errorf("creating database specific entry: %w", err)
			}
			rec.DatabaseSpecific = dbs

			// Append the record to the OSV predicate
			ret.Parsed.Records = append(ret.Parsed.Records, rec)
		}
	}
	return ret, nil
}
