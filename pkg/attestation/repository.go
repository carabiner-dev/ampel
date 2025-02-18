// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

type Repository interface{}

// AttestationFetcher is the the trait that repositories that can fetch
// attestations must implement
type Fetcher interface {
	Fetch(...FetchOptionsFunc) ([]Envelope, error)
	FetchAttestationsBySubject([]Subject, ...FetchOptionsFunc) ([]Envelope, error)
	FetchAttestationsByPredicateType(PredicateType, ...FetchOptionsFunc) ([]Envelope, error)
}

type Storer interface {
	Store([]Envelope) error
}

// StoreOptions control how attestations are retrieved from a Fetcher. All
// repositories implementing the Fetcher interface are expected to honor FetchOptions.
type FetchOptions struct {
	Query *Query
}

// StoreOptions control how attestations are stored in the storer. All repositories
// implementing the Storer interface are expected to honor StoreOptions.
type StoreOptions struct{}

// FetchOptionsFunc are functions to define options when fetching
type FetchOptionsFunc func(*FetchOptions)

// WithQuery passes a query to the options set
func WithQuery(q *Query) FetchOptionsFunc {
	return func(opts *FetchOptions) {
		opts.Query = q
	}
}

// StoreOptionsFunc are functions to define options when fetching
type StoreOptionsFunc func(*StoreOptions)
