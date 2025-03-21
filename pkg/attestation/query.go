// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

const (
	QueryModeOr  = "OR"
	QueryModeAnd = "AND"
)

func NewQuery() *Query {
	return &Query{
		Filters: FilterSet{},
	}
}

// Query controls the evaluation of a group of filters.
type Query struct {
	Filters FilterSet
}

// A filter abstracts logic that looks into an attestation's properties
// to determine if it matches some criteria.
type Filter interface {
	Matches(Envelope) bool
}

// QueryOptions
type QueryOptions struct {
	Mode string
}

var defaultOptions = QueryOptions{
	Mode: QueryModeAnd,
}

type optFunc func(*QueryOptions)

var WithMode = func(mode string) optFunc {
	return func(qo *QueryOptions) {
		if mode == QueryModeAnd || mode == QueryModeOr {
			qo.Mode = mode
		}
	}
}

// Run executes the query, running the attestations through the filters
// and returning those that match.
func (query *Query) Run(atts []Envelope, funcs ...optFunc) []Envelope {
	opts := defaultOptions
	for _, f := range funcs {
		f(&opts)
	}

	newset := []Envelope{}
	for _, att := range atts {
		switch opts.Mode {
		case QueryModeAnd:
			if query.Filters.MatchesAll(att) {
				newset = append(newset, att)
			}
		case QueryModeOr:
			if query.Filters.MatchesOne(att) {
				newset = append(newset, att)
			}
		}
	}
	return newset
}

// WithFilter adds a filter to the Query
func (query *Query) WithFilter(filters ...Filter) *Query {
	query.Filters = append(query.Filters, filters...)
	return query
}

// Filterset is a group of filters that forma query
type FilterSet []Filter

// Matches returns a bool indicating if all filters match an envelope
func (fs FilterSet) MatchesAll(att Envelope) bool {
	for _, f := range fs {
		if !f.Matches(att) {
			return false
		}
	}
	return true
}

// Matches returns a bool indicating if the attestaion matches at least one
// of the filters
func (fs FilterSet) MatchesOne(att Envelope) bool {
	for _, f := range fs {
		if f.Matches(att) {
			return true
		}
	}
	return false
}

// FilterList runs a list of attestations through the configured filters and
// returns a new list with those that match.
func (fs FilterSet) FilterList(in []Envelope, funcs ...optFunc) []Envelope {
	opts := defaultOptions
	for _, f := range funcs {
		f(&opts)
	}

	newset := []Envelope{}
	for _, att := range in {
		switch opts.Mode {
		case QueryModeAnd:
			if fs.MatchesAll(att) {
				newset = append(newset, att)
			}
		case QueryModeOr:
			if fs.MatchesOne(att) {
				newset = append(newset, att)
			}
		}
	}
	return newset
}
