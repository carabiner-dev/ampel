// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulnreport

import (
	"errors"
	"fmt"
	"time"

	posv "github.com/carabiner-dev/osv/go/osv"
	"github.com/puerco/ampel/pkg/formats/predicate/osv"
	"github.com/puerco/ampel/pkg/formats/predicate/trivy"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// trivyToOSV converts a trivy v2 output to an OSV feed
func (t *Transformer) TrivyToOSV(original *trivy.Predicate) (*osv.Predicate, error) {
	if original == nil {
		return nil, errors.New("original predicate undefined")
	}

	createdat := time.Now()
	if original.Parsed.CreatedAt != nil {
		createdat = *original.Parsed.CreatedAt
	}

	ret := &osv.Predicate{
		Parsed: &posv.Results{
			Date: timestamppb.New(createdat),
			Results: []*posv.Result{
				{
					Source: &posv.Result_Source{
						Path: original.Parsed.ArtifactName,
						Type: original.Parsed.ArtifactType,
					},
					Packages: []*posv.Result_Package{
						{
							Package: &posv.Result_Package_Info{
								Name: original.Parsed.ArtifactName,
							},
							Vulnerabilities: []*posv.Record{},
						},
					},
				},
			},
		},
	}

	results := map[string][]*posv.Record{}

	for _, result := range original.Parsed.Results {
		for _, vuln := range result.Vulnerabilities {
			// Check if we have a collection for this one
			rec := &posv.Record{
				SchemaVersion: posv.Version,
				Id:            vuln.VulnerabilityID,
				Aliases:       []string{},
				Related:       []string{},
				Summary:       vuln.Title,
				Details:       vuln.Description,
				Severity:      []*posv.Severity{},
				Affected: []*posv.Affected{
					{
						Package: &posv.Package{
							Name: vuln.PkgName,
						},
						Severity:          []*posv.Severity{},
						Ranges:            []*posv.Range{},
						Versions:          []string{},
						EcosystemSpecific: &structpb.Struct{},
						DatabaseSpecific:  &structpb.Struct{},
					},
				},
				References: []*posv.Reference{},
				Credits:    []*posv.Credit{},
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
				rec.References = append(rec.References, &posv.Reference{
					Type: "URL",
					Url:  r,
				})
			}

			// Add the severities
			for _, cvss := range vuln.CVSS {
				rec.Severity = append(rec.Severity, &posv.Severity{
					Type:  "CVSS_V3",
					Score: fmt.Sprintf("%.1f", cvss.V3Score),
				})
			}

			// Compute a range with the versions
			rec.Affected[0].Ranges = append(rec.Affected[0].Ranges, &posv.Range{
				Type: "SEMVER",
				Events: []*posv.Range_Event{
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
					// TODO(puerco): Fix this, the []string does not serialize
					//"CWE":      vuln.CweIDs,
					"KEV": "",
				},
			})
			if err != nil {
				return nil, fmt.Errorf("creating database specific entry: %w", err)
			}
			rec.DatabaseSpecific = dbs

			// Append the record to the OSV predicate
			if _, ok := results[vuln.PkgName]; !ok {
				results[vuln.PkgName] = []*posv.Record{}
			}
			results[vuln.PkgName] = append(results[vuln.PkgName], rec)
		}
	}

	for name, records := range results {
		pkg := &posv.Result_Package{
			Package: &posv.Result_Package_Info{
				Name: name,
			},
			Vulnerabilities: []*posv.Record{},
		}
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, records...)
		ret.Parsed.Results[0].Packages = append(ret.Parsed.Results[0].Packages, pkg)
	}

	return ret, nil
}
