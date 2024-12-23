package collector

import (
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/policy"
	"github.com/puerco/ampel/pkg/principal"
)

type AttestationQuery struct{}

type Repository interface {
}

type Fetcher interface {
	Fetch(AttestationQuery) ([]*attestation.Statement, error)
	FetchObjectStatements(principal.Object) ([]attestation.Statement, error)
}

type PolicyStorageKey string

type PolicyStore interface {
	ListPolicies() ([]*policy.Checklist, error)
	FetchPolicy(PolicyStorageKey) (*policy.Checklist, error)
}

type Storer interface {
	Store(*attestation.Statement) error
}

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
