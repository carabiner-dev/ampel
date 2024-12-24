package collector

import (
	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/collector/filter"
)

type Repository interface {
}

type FetchOptions struct {
	Query filter.AttestationQuery
}

type AttestationFetcher interface {
	Fetch(*FetchOptions) ([]attestation.Envelope, error)
	FetchObjectStatements(attestation.Subject) ([]attestation.Envelope, error)
}

type PolicyStorageKey string

type PolicyStore interface {
	ListPolicies() ([]*v1.PolicySet, error)
	FetchPolicy(PolicyStorageKey) (*v1.PolicySet, error)
}

type Storer interface {
	Store(attestation.Envelope) error
}

type RepoFilter func([]Repository) []Repository

// FilterFetchers returns the repositories that support fetching
var FilterFetchers = func(repos []Repository) []Repository {
	repos = []Repository{}
	for _, r := range repos {
		if _, ok := r.(AttestationFetcher); ok {
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

// FilterPolicyStore returns the repositories that support fetching
var FilterPolicyStore = func(repos []Repository) []Repository {
	repos = []Repository{}
	for _, r := range repos {
		if _, ok := r.(PolicyStore); ok {
			repos = append(repos, r)
		}
	}
	return repos
}

// FilterRepos
func FilterRepos(repos []Repository, filters ...RepoFilter) []Repository {
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
