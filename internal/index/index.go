// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"slices"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"
)

func New(funcs ...constructorFunc) (*StatementIndex, error) {
	si := &StatementIndex{}
	for _, fn := range funcs {
		if err := fn(si); err != nil {
			return nil, err
		}
	}
	return si, nil
}

type constructorFunc func(*StatementIndex) error

func WithDocument(doc *vex.VEX) constructorFunc {
	return func(si *StatementIndex) error {
		statements := []*vex.Statement{}
		for _, s := range doc.Statements {
			statements = append(statements, &s)
		}
		si.IndexStatements(statements)
		return nil
	}
}

func WithStatements(statements []*vex.Statement) constructorFunc {
	return func(si *StatementIndex) error {
		si.IndexStatements(statements)
		return nil
	}
}

type StatementIndex struct {
	VulnIndex map[string][]*vex.Statement
	ProdIndex map[string][]*vex.Statement
	SubIndex  map[string][]*vex.Statement
}

// IndexStatements
func (si *StatementIndex) IndexStatements(statements []*vex.Statement) {
	si.VulnIndex = map[string][]*vex.Statement{}
	si.ProdIndex = map[string][]*vex.Statement{}
	si.SubIndex = map[string][]*vex.Statement{}
	logrus.Infof("Indexer: Indexing %d statements", len(statements))
	for _, s := range statements {
		for _, p := range s.Products {
			for _, id := range p.Identifiers {
				si.ProdIndex[id] = append(si.ProdIndex[id], s)
			}
			for _, h := range p.Hashes {
				si.ProdIndex[string(h)] = append(si.ProdIndex[string(h)], s)
			}

			// Index the subcomponents
			for _, sc := range p.Subcomponents {
				for _, id := range sc.Identifiers {
					si.SubIndex[id] = append(si.SubIndex[id], s)
				}
				for _, h := range sc.Hashes {
					si.SubIndex[string(h)] = append(si.SubIndex[string(h)], s)
				}
			}
		}

		if s.Vulnerability.Name != "" {
			si.VulnIndex[string(s.Vulnerability.Name)] = append(si.VulnIndex[string(s.Vulnerability.Name)], s)
		}
		for _, alias := range s.Vulnerability.Aliases {
			si.VulnIndex[string(alias)] = append(si.VulnIndex[string(alias)], s)
		}
	}
}

type Filter func() map[*vex.Statement]struct{}

type FilterFunc func(*StatementIndex) Filter

func WithVulnerability(vuln *vex.Vulnerability) FilterFunc {
	return func(si *StatementIndex) Filter {
		return func() map[*vex.Statement]struct{} {
			ret := map[*vex.Statement]struct{}{}
			ids := []vex.VulnerabilityID{}
			if vuln.Name != "" {
				ids = append(ids, vuln.Name)
			}
			ids = append(ids, vuln.Aliases...)

			for _, id := range ids {
				for _, s := range si.VulnIndex[string(id)] {
					ret[s] = struct{}{}
				}
			}
			return ret
		}
	}
}

func WithProduct(prod *vex.Product) FilterFunc {
	return func(si *StatementIndex) Filter {
		return func() map[*vex.Statement]struct{} {
			ret := map[*vex.Statement]struct{}{}
			ids := []string{}
			for _, id := range prod.Identifiers {
				ids = append(ids, id)
			}
			for _, h := range prod.Hashes {
				ids = append(ids, string(h))
			}

			for _, id := range ids {
				for _, s := range si.ProdIndex[string(id)] {
					ret[s] = struct{}{}
				}
			}

			return ret
		}
	}
}

func WithSubcomponent(subc *vex.Subcomponent) FilterFunc {
	return func(si *StatementIndex) Filter {
		return func() map[*vex.Statement]struct{} {
			ret := map[*vex.Statement]struct{}{}
			ids := []string{}
			for _, id := range subc.Identifiers {
				ids = append(ids, id)
			}
			for _, h := range subc.Hashes {
				ids = append(ids, string(h))
			}

			for _, id := range ids {
				for _, s := range si.SubIndex[string(id)] {
					ret[s] = struct{}{}
				}
			}

			return ret
		}
	}
}

// unionIndexResults
func unionIndexResults(results []map[*vex.Statement]struct{}) []*vex.Statement {
	if len(results) == 0 {
		return []*vex.Statement{}
	}
	preret := map[*vex.Statement]struct{}{}
	// Since we're looking for statements in all results, we can just
	// cycle the shortest list against the others
	slices.SortFunc(results, func(a, b map[*vex.Statement]struct{}) int {
		if len(a) == len(b) {
			return 0
		}
		if len(a) < len(b) {
			return -1
		}
		return 1
	})

	var found bool
	for s := range results[0] {
		// if this is present in all lists, we're in
		found = true
		for i := range results[1:] {
			if _, ok := results[i][s]; !ok {
				found = false
				break
			}
		}
		if found {
			preret[s] = struct{}{}
		}
	}

	// Now assemble the list
	ret := []*vex.Statement{}
	for s := range preret {
		ret = append(ret, s)
	}
	return ret
}

// Matches applies filters to the index to look for matching statements
func (si *StatementIndex) Matches(filterfunc ...FilterFunc) []*vex.Statement {
	lists := []map[*vex.Statement]struct{}{}
	for _, ffunc := range filterfunc {
		filter := ffunc(si)
		lists = append(lists, filter())
	}
	return unionIndexResults(lists)
}
