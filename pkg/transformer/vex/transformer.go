// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package vex is a transformer that reads in a vulnerability report
// and a number of VEX documents and supresses those that do not affect
// the subject
package vex

import (
	"slices"

	gointoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/ampel/internal/index"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	aosv "github.com/carabiner-dev/ampel/pkg/formats/predicate/osv"
	"github.com/carabiner-dev/osv/go/osv"
	openvex "github.com/openvex/go-vex/pkg/vex"
)

// Transformer implements the VEX interface
type Transformer struct {
}

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

// ApplyVEX applies a group of OpenVEX predicates to the vuln report
// and returns the vexed report
func (t *Transformer) ApplyVEX(
	subj attestation.Subject, report *osv.Results, vexes []attestation.Predicate,
) (attestation.Predicate, error) {
	// Filter the applicable statements
	statements := extractStatements(vexes)

	// Index the statements
	si := index.StatementIndex{}
	si.IndexStatements(statements)
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
	statements = si.Matches(index.WithProduct(&product))
	productIndex := index.StatementIndex{}
	productIndex.IndexStatements(statements)

	newReport := &osv.Results{
		Date:    report.GetDate(),
		Results: []*osv.Result{},
	}

	// This sucks, we need better indexing in the vex libraries
	for i, result := range report.Results {
		for _, p := range result.GetPackages() {
			newpackage := osv.Result_Package{}
			// Assemble the filter pieces. First, the vuln:
			for _, v := range p.Vulnerabilities {
				ovuln := openvex.Vulnerability{
					Name: openvex.VulnerabilityID(v.GetId()),
				}
				for _, a := range v.Aliases {
					ovuln.Aliases = append(ovuln.Aliases, openvex.VulnerabilityID(a))
				}

				var subcs = []*openvex.Subcomponent{}
				for _, af := range v.Affected {
					if af.GetPackage() == nil {
						continue
					}
					if af.GetPackage().GetPurl() == "" {
						continue
					}
					subcs = append(subcs, &openvex.Subcomponent{
						Component: openvex.Component{
							Identifiers: map[openvex.IdentifierType]string{
								openvex.PURL: af.Package.GetPurl(),
							},
						},
					})
				}

				// TODO: Apply filters and get statements
			}

			if len(newpackage.Vulnerabilities) > 0 {
				newReport.GetResults()[i].Packages = append(newReport.GetResults()[i].Packages, &newpackage)
			}
		}
	}

	return &generic.Predicate{
		Type:   aosv.PredicateType,
		Parsed: newReport,
		Source: nil,
		Data:   []byte{}, // Marshal
	}, nil
}

// extractStatements reads all the openvex predicates the statements
func extractStatements(preds []attestation.Predicate) []*openvex.Statement {
	ret := []*openvex.Statement{}
	for _, pred := range preds {
		doc, ok := pred.GetParsed().(openvex.VEX)
		if !(ok) {
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

func filterStatements(subject attestation.Subject, preds []attestation.Predicate) ([]*openvex.Statement, error) {
	indexed := map[int64][]*openvex.Statement{}
	times := []int64{}
	for _, pred := range preds {
		doc, ok := pred.GetParsed().(openvex.VEX)
		if !(ok) {
			continue
		}

		// Capture the doc date as its the time the statements
		// default when they don't have a defined timestamp
		docTime := doc.Timestamp
		if doc.LastUpdated != nil {
			docTime = doc.LastUpdated
		}

		// Cycle the VEX statements to index them by date
		for _, s := range doc.Statements {
			// Check if the vex product matches the subject
			match := false
			for _, hash := range subject.GetDigest() {
				if s.MatchesProduct(hash, "") {
					match = true
					break
				}
				// We can also match identifiers and name but since
				// we are dealing with attestatons, most will have
				// hashes, implement later if needed.
			}
			if !match {
				continue
			}

			// Compute the effecrtive time
			d := docTime
			// First, pick the date
			if s.Timestamp != nil {
				d = s.Timestamp
			}
			if s.LastUpdated != nil {
				d = s.LastUpdated
			}

			if _, ok := indexed[d.Unix()]; !ok {
				indexed[d.Unix()] = []*openvex.Statement{}
				times = append(times, d.Unix())
			}
			indexed[d.Unix()] = append(indexed[d.Unix()], &s)
		}
	}
	slices.Sort(times)
	ret := []*openvex.Statement{}
	for _, t := range times {
		ret = append(ret, indexed[t]...)
	}
	return ret, nil
}
