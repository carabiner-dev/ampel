// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type compilerImplementation interface {
	ValidateSet(*CompilerOptions, *api.PolicySet) error
	ExtractRemoteReferences(*CompilerOptions, *api.PolicySet) ([]*api.PolicyRef, error)
	FetchRemoteResources(*CompilerOptions, StorageBackend, []*api.PolicyRef) error
	ValidateRemotes(*CompilerOptions, StorageBackend) error
	AssemblePolicySet(*CompilerOptions, *api.PolicySet, StorageBackend) error
	ValidateAssebledSet(*CompilerOptions, *api.PolicySet) error
}

type defaultCompilerImpl struct{}

func (dci *defaultCompilerImpl) ValidateSet(*CompilerOptions, *api.PolicySet) error {
	// TODO(puerco): Implement with learnings from building this
	// Rules:
	//   Check if same uri has different hashes
	//   Check for same version in same uri
	//
	// Post rules:
	//   Remote ID is not the reference id
	//
	return nil
}

// ExtractRemoteReferences extracts and enriches the remote references from all
// information available in (possibly) repeatead remote references.
func (dci *defaultCompilerImpl) ExtractRemoteReferences(_ *CompilerOptions, set *api.PolicySet) ([]*api.PolicyRef, error) {
	ret := []*api.PolicyRef{}
	uriIndex := map[string]*api.PolicyRef{}
	for _, ref := range set.References {
		if ref.GetLocation() == nil {
			continue
		}

		// Check if the policy has a DownloadLocation
		url := ref.GetLocation().GetDownloadLocation()
		if url == "" {
			url = ref.GetLocation().GetUri()
		}
		if url == "" {
			continue
		}

		if _, ok := uriIndex[url]; !ok {
			uriIndex[url] = ref
			continue
		}

		if uriIndex[url].GetVersion() != ref.GetVersion() && uriIndex[url].GetVersion() != 0 && ref.GetVersion() != 0 {
			return nil, fmt.Errorf("inconsistency detected: version clash in remote refs")
		}

		if uriIndex[url].GetVersion() == 0 {
			uriIndex[url].Version = ref.GetVersion()
		}

		for algo, val := range ref.GetLocation().GetDigest() {
			if v, ok := uriIndex[url].Location.Digest[algo]; ok {
				if v != val {
					return nil, fmt.Errorf("inconsistency detected, hash values clash")
				}
			}
			uriIndex[url].Location.Digest[algo] = val
		}
	}

	// Assemble the slice and return
	for _, ref := range uriIndex {
		ret = append(ret, ref)
	}

	return ret, nil
}

// FetchRemoteResources pulls all the remote data in parallel and stores it
// int
func (dci *defaultCompilerImpl) FetchRemoteResources(_ *CompilerOptions, store StorageBackend, refs []*api.PolicyRef) error {
	if store == nil {
		return errors.New("storage backend missing")
	}
	fetcher := NewFetcher()

	// Extract the URIs
	uris := make([]string, len(refs))
	for i, ref := range refs {
		// Check if the policy has a DownloadLocation
		uri := ref.GetLocation().GetDownloadLocation()
		if uri == "" {
			uri = ref.GetLocation().GetUri()
		}
		uris[i] = uri
	}

	// Retrieve the remote data
	data, err := fetcher.GetGroup(uris)
	if err != nil {
		return fmt.Errorf("fetching remote data: %w", err)
	}

	// Store the retrieved data in the resource descriptor
	for i, datum := range data {
		// Here we shoud validate any hashes we have
		refs[i].Location.Content = datum

		// Store the reference
		if err := store.StoreReference(refs[i]); err != nil {
			return fmt.Errorf("storing external ref #%d: %w", i, err)
		}
	}

	return nil
}

func (dci *defaultCompilerImpl) ValidateRemotes(*CompilerOptions, StorageBackend) error {
	return nil
}

func (dci *defaultCompilerImpl) AssemblePolicySet(_ *CompilerOptions, set *api.PolicySet, store StorageBackend) error {
	for i, p := range set.Policies {
		// If the policy does not hava remote source, skip
		if p.Source == nil {
			continue
		}
		remotePolicy, err := store.GetReferencedPolicy(p.Source)
		if err != nil {
			return fmt.Errorf("getting referenced policy: %w", err)
		}

		if remotePolicy == nil {
			return fmt.Errorf("unable to complete policy #%d, reference not resolved", i)
		}

		assembledPolicy, ok := proto.Clone(remotePolicy).(*api.Policy)
		if !ok {
			return fmt.Errorf("unable to cast reassembled policy #%d: %w", i, err)
		}

		// Merge the local policy changes onto the remote:
		proto.Merge(assembledPolicy, p)
		assembledPolicy.Source = nil

		// Now replace the local in the policy set with the enriched remote
		set.Policies[i] = assembledPolicy
	}
	set.References = nil
	return nil
}

func (dci *defaultCompilerImpl) ValidateAssebledSet(*CompilerOptions, *api.PolicySet) error {
	return nil
}
