// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"fmt"
	"sync"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

var repositoryTypes = map[string]RepositoryFactory{}

type RepositoryFactory func(string) (attestation.Repository, error)

var mtx sync.Mutex

// RegisterCollectorType registers a new type of collector
func RegisterCollectorType(moniker string, factory RepositoryFactory) error {
	if _, ok := repositoryTypes[moniker]; ok {
		return fmt.Errorf("collector %q is already registered", moniker)
	}
	mtx.Lock()
	repositoryTypes[moniker] = factory
	mtx.Unlock()
	return nil
}

// RegisterCollectorType registers a new type of collector
func UnregisterCollectorType(moniker string) {
	delete(repositoryTypes, moniker)
}
