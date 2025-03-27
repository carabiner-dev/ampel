// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"github.com/carabiner-dev/ampel/pkg/attestation"
)

type repoFilter func([]attestation.Repository) any

// filterRepositories takes a list of configured repositories and returns those
// that match a capability filter.
func (agent *Agent) filterRepositories(filter repoFilter) any {
	return filter(agent.Repositories)
}

// fetcherRepos returns the list of configured repositories that implement the
// Fetcher trait.
func (agent *Agent) fetcherRepos() []attestation.Fetcher {
	res := agent.filterRepositories(func(repos []attestation.Repository) any {
		filtered := []attestation.Fetcher{}
		for _, r := range repos {
			if f, ok := r.(attestation.Fetcher); ok {
				filtered = append(filtered, f)
			}
		}
		return filtered
	})
	return res.([]attestation.Fetcher)
}

// storerRepos returns the list of configured repositories that implement the
// Storer trait.
func (agent *Agent) storerRepos() []attestation.Storer {
	res := agent.filterRepositories(func(repos []attestation.Repository) any {
		filtered := []attestation.Repository{}
		for _, r := range repos {
			if _, ok := r.(attestation.Storer); ok {
				filtered = append(filtered, r)
			}
		}
		return filtered
	})
	return res.([]attestation.Storer)
}
