// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

// Query controls the evaluation of a group of filters.
type Query struct {
	Filters FilterSet
}

// A filter abstracts logic that looks into an attestation's properties
// to determine if it matches some criteria.
type Filter interface {
	Matches(Envelope) bool
}

// Run executes the query, running the attestations through the filters
// and returning those that match.
func (query *Query) Run(atts []Envelope) []Envelope {
	newset := []Envelope{}
	for _, att := range atts {
		if !query.Filters.Matches(att) {
			continue
		}
		newset = append(newset, att)
	}
	return newset
}

// WithFilter adds a filter to the Query
func (query *Query) WithFilter(f Filter) *Query {
	query.Filters = append(query.Filters, f)
	return query
}

// Filterset is a group of filters that forma query
type FilterSet []Filter

// Matches returns a bool indicating if all filters match an envelope
func (fs FilterSet) Matches(att Envelope) bool {
	for _, f := range fs {
		if !f.Matches(att) {
			return false
		}
	}
	return true
}
