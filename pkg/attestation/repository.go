// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

type Repository interface{}
type RepoFilter func([]Repository) []Repository

// FilterFetchers returns the repositories that support fetching
var FilterFetchers = func(repos []Repository) []Repository {
	repos = []Repository{}
	for _, r := range repos {
		if _, ok := r.(Fetcher); ok {
			repos = append(repos, r)
		}
	}
	return repos
}

// FilterFetchers returns the repositories that support fetching
var FilterStorers = func(repos []Repository) []Repository {
	repos = []Repository{}
	for _, r := range repos {
		if _, ok := r.(Storer); ok {
			repos = append(repos, r)
		}
	}
	return repos
}

// FilterRepositories takes a list of configured repositories and returns those
// that match a capability filter.
func FilterRepositories(repos []Repository, filters ...RepoFilter) []Repository {
	res := []Repository{}
	if len(filters) == 0 {
		return res
	}

	filteredRepos := map[Repository]struct{}{}

	for _, f := range filters {
		fr := f(repos)
		for _, r := range fr {
			filteredRepos[r] = struct{}{}
		}
	}

	for r := range filteredRepos {
		res = append(res, r)
	}
	return res
}

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
