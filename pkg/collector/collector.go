// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
)

type PolicyStorageKey string

type PolicyStore interface {
	ListPolicies() ([]*v1.PolicySet, error)
	FetchPolicy(PolicyStorageKey) (*v1.PolicySet, error)
}

// FilterPolicyStore returns the repositories that support fetching
var FilterPolicyStore = func(repos []attestation.Repository) []attestation.Repository {
	repos = []attestation.Repository{}
	for _, r := range repos {
		if _, ok := r.(PolicyStore); ok {
			repos = append(repos, r)
		}
	}
	return repos
}
