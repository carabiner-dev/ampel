// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/repository/filesystem"
	"github.com/carabiner-dev/ampel/pkg/repository/github"
	"github.com/carabiner-dev/ampel/pkg/repository/jsonl"
	"github.com/carabiner-dev/ampel/pkg/repository/note"
	"github.com/carabiner-dev/ampel/pkg/repository/release"
)

var (
	repositoryTypes          = map[string]RepositoryFactory{}
	ErrTypeAlreadyRegistered = errors.New("collector type already registered")
)

type RepositoryFactory func(string) (attestation.Repository, error)

var mtx sync.Mutex

func RepositoryFromString(init string) (attestation.Repository, error) {
	t, init, _ := strings.Cut(init, ":")
	if b, ok := repositoryTypes[t]; ok {
		return b(init)
	}
	return nil, fmt.Errorf("repository type unknown: %q", t)
}

// RegisterCollectorType registers a new type of collector
func RegisterCollectorType(moniker string, factory RepositoryFactory) error {
	if _, ok := repositoryTypes[moniker]; ok {
		return ErrTypeAlreadyRegistered
	}
	mtx.Lock()
	repositoryTypes[moniker] = factory
	mtx.Unlock()
	return nil
}

// RegisterCollectorType registers a new type of collector
func UnregisterCollectorType(moniker string) {
	mtx.Lock()
	delete(repositoryTypes, moniker)
	mtx.Unlock()
}

func LoadDefaultRepositoryTypes() error {
	errs := []error{}
	for t, factory := range map[string]RepositoryFactory{
		filesystem.TypeMoniker: filesystem.Build,
		jsonl.TypeMoniker:      jsonl.Build,
		github.TypeMoniker:     github.Build,
		release.TypeMoniker:    release.Build,
		note.TypeMoniker:       note.Build,
	} {
		if err := RegisterCollectorType(t, factory); err != nil {
			if !errors.Is(err, ErrTypeAlreadyRegistered) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
