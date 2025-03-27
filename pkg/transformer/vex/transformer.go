// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package vex is a transformer that reads in a vulnerability report
// and a number of VEX documents and supresses those that do not affect
// the subject
package vex

import (
	"fmt"
	"slices"
	"strings"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/carabiner-dev/ampel/internal/index"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	aosv "github.com/carabiner-dev/ampel/pkg/formats/predicate/osv"
	"github.com/carabiner-dev/osv/go/osv"
	openvex "github.com/openvex/go-vex/pkg/vex"
)

// Transformer implements the VEX interface
type Transformer struct{}

// Mutate applies the VEX documents in the input to the received
// vulnerability reports.
func (t *Transformer) Mutate(subj attestation.Subject, inputs []attestation.Predicate) ([]attestation.Predicate, error) {
	return nil, nil
}

func hashToHash(intotoHash string) string {
	switch intotoHash {
	case string(gointoto.AlgorithmSHA256):
		return string(openvex.SHA256)
	case string(gointoto.AlgorithmSHA512):
		return string(openvex.SHA512)
	case string(gointoto.AlgorithmSHA1), string(gointoto.AlgorithmGitCommit), string(gointoto.AlgorithmGitTag):
		return string(openvex.SHA1)
	default:
		return ""
	}
}

// This converts an ecosystem package to a purl. For the full list
// of officially supported ecosystems see the file in this bucket:
// https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
func osvPackageToPurl(pkg *osv.Result_Package_Info) string {
	var ptype, version, namespacename string
	switch pkg.GetEcosystem() {
	case "Go":
		ptype = "golang"
		version = pkg.GetVersion()
		namespacename = pkg.GetName()
	default:
		return ""
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ptype, namespacename, version)
}

func normalizeVulnIds(record *osv.Record) (openvex.VulnerabilityID, []openvex.VulnerabilityID) {
	id := openvex.VulnerabilityID(record.GetId())
	alias := []openvex.VulnerabilityID{id}
	for _, i := range record.Aliases {
		if strings.HasPrefix(i, "CVE-") {
			id = openvex.VulnerabilityID(i)
		}
		if !slices.Contains(alias, openvex.VulnerabilityID(i)) {
			alias = append(alias, openvex.VulnerabilityID(i))
		}
	}

	slices.Sort(alias)

	return id, alias
}

// ApplyVEX applies a group of OpenVEX predicates to the vuln report
// and returns the vexed report
func (t *Transformer) ApplyVEX(
	subj attestation.Subject, report *osv.Results, vexes []attestation.Predicate,
) (attestation.Predicate, error) {
	// Filter the applicable statements
	statements := extractStatements(vexes)
	logrus.Infof("Filtered %d statements from %d OpenVEX predicates", len(statements), len(vexes))

	// Create the vex product from the policy subject
	hashes := map[openvex.Algorithm]openvex.Hash{}
	for algo, val := range subj.GetDigest() {
		h := hashToHash(algo)
		if h == "" {
			continue
		}
		hashes[openvex.Algorithm(h)] = openvex.Hash(val)
	}
	product := openvex.Product{}
	product.Hashes = hashes

	// Index the statements and get those that apply
	si, err := index.New(index.WithStatements(statements))
	if err != nil {
		return nil, fmt.Errorf("creating statement index")
	}
	logrus.Infof("VEX Index: %+v", si)
	statements = si.Matches(index.WithProduct(&product))
	logrus.Infof("Got %d statatements back applicable to product %+v", len(statements), product)

	// Now index the applicable statements
	productIndex, err := index.New(index.WithStatements(statements))
	if err != nil {
		return nil, fmt.Errorf("indexing produc statements: %w", err)
	}

	newReport := &osv.Results{
		Date:    report.GetDate(),
		Results: []*osv.Result{},
	}

	// This sucks, we need better indexing in the vex libraries
	for _, result := range report.Results {
		// Clone the result to the new one
		newResult := proto.CloneOf(result)
		newResult.Packages = []*osv.Result_Package{}

		for _, p := range result.GetPackages() {
			// Comput the package URL for the purl
			packagePurl := osvPackageToPurl(p.GetPackage())
			if packagePurl == "" {
				logrus.Infof("Could not build purl from %+v, no matching possible", p)
				newResult.Packages = append(newResult.Packages, p)
				continue
			}

			// Clone the package entry, but reset the vulnerabilities
			newPackage := proto.CloneOf(p)
			newPackage.Vulnerabilities = []*osv.Record{}

			logrus.Infof("Checking vulns for %s", packagePurl)

			// Assemble the filter pieces. First, the vuln:
			for _, v := range p.Vulnerabilities {
				id, aliases := normalizeVulnIds(v)
				ovuln := openvex.Vulnerability{
					Name:    id,
					Aliases: aliases,
				}

				logrus.Infof("  Checking vexes for %s %+v", ovuln.Name, ovuln.Aliases)

				// Note that the scanner puts the affected package at the top
				// of the result struct, so no need to descend to the affected
				// data of the report.
				subc := &openvex.Subcomponent{
					Component: openvex.Component{
						ID: packagePurl,
						Identifiers: map[openvex.IdentifierType]string{
							openvex.PURL: packagePurl,
						},
					},
				}

				pstatements := productIndex.Matches(
					index.WithVulnerability(&ovuln),
					index.WithSubcomponent(subc),
				)
				logrus.Infof("  VEX Index: %+v", productIndex)
				logrus.Infof("  Got %d vex statements from indexer for %s + %s", len(pstatements), ovuln.Name, subc.ID)

				var statement *openvex.Statement
				for _, s := range pstatements {
					if statement == nil {
						statement = s
						continue
					}

					d := s.Timestamp
					if s.LastUpdated != nil {
						if s.LastUpdated.After(*d) {
							d = s.LastUpdated
						}
					}

					st := statement.Timestamp
					if statement.LastUpdated != nil {
						st = statement.LastUpdated
					}

					if d.After(*st) {
						statement = s
					}
				}

				// At this point we have the latest vex statement, we can now
				// check if we're not_affected :lolsob:
				if statement != nil && statement.Status == openvex.StatusNotAffected {
					logrus.Infof("VEX data found for %s in %s, suppressing", v.GetId(), packagePurl)
					continue
				}

				// ... if not, then inlucde it in the new one.
				newPackage.Vulnerabilities = append(newPackage.Vulnerabilities, v)
			}

			if len(newPackage.Vulnerabilities) > 0 {
				newResult.Packages = append(newResult.Packages, newPackage)
			} else {
				logrus.Infof("Vulnerabilities in %s are vexed. Skipping from report", packagePurl)
			}
		}
		newReport.Results = append(newReport.Results, newResult)
	}

	data, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(newReport)
	if err != nil {
		return nil, fmt.Errorf("marshaling new OSV report")
	}

	return &generic.Predicate{
		Type:   aosv.PredicateType,
		Parsed: newReport,
		Data:   data,
	}, nil
}

// extractStatements reads all the openvex predicates the statements
func extractStatements(preds []attestation.Predicate) []*openvex.Statement {
	ret := []*openvex.Statement{}
	for _, pred := range preds {
		doc, ok := pred.GetParsed().(*openvex.VEX)
		if !(ok) {
			logrus.Info("No es")
			continue
		}

		// Cycle the VEX statements
		// TODO: This should be a doc.ExtractStatement func
		for _, s := range doc.Statements {
			// Carry over the dates from the doc
			if s.Timestamp == nil {
				s.Timestamp = doc.Timestamp
			}
			if s.LastUpdated != nil {
				s.LastUpdated = doc.LastUpdated
			}
			ret = append(ret, &s)
		}
	}
	return ret
}
