// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"slices"

	"github.com/sirupsen/logrus"
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
	// Add all the references we have, first the set-level refs:
	refs := []*api.PolicyRef{}
	if set.GetCommon() != nil && set.GetCommon().GetReferences() != nil {
		refs = append(refs, set.GetCommon().GetReferences()...)
	}
	// ... and all policy sources
	for _, p := range set.Policies {
		if p.GetSource() != nil {
			refs = append(refs, p.GetSource())
		}
	}

	ret, err := groupRemoteRefs(refs)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func groupRemoteRefs(refs []*api.PolicyRef) ([]*api.PolicyRef, error) {
	uriIndex := map[string]*api.PolicyRef{}
	ret := []*api.PolicyRef{}

	// Rage over all refs and extract the ones that point to remote resources
	for _, ref := range refs {
		// If it does not have location coordinates, skip it
		if ref.GetLocation() == nil {
			continue
		}

		// Check if the policy has a DownloadLocation
		if ref.GetSourceURL() == "" {
			continue
		}

		url := ref.GetSourceURL()
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
					return nil, fmt.Errorf("inconsistency detected, hash values clash for URI %s", url)
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

func fetchRemoteResources(
	_ *CompilerOptions, recurse int, store StorageBackend, refs []*api.PolicyRef,
) error {
	// Extract the URIs
	uris := []string{}
	newRefs := []*api.PolicyRef{}
	for _, ref := range refs {
		p, err := store.GetReferencedPolicy(ref)
		if err != nil {
			return fmt.Errorf("checking cached copy of referenced policy: %w", err)
		}
		// If we already have a copy, skip
		if p != nil {
			continue
		}

		// Check if the policy has a DownloadLocation
		uri := ref.GetLocation().GetDownloadLocation()
		if uri == "" {
			uri = ref.GetLocation().GetUri()
		}
		uris = append(uris, uri)
		newRefs = append(newRefs, ref)
	}

	if len(uris) == 0 {
		logrus.Debugf("No remote resources required to fetch (from %d refs)", len(refs))
		return nil
	}

	logrus.Debugf("Fetching remote references (depth %d): %+v", recurse, uris)

	// Retrieve the remote data
	data, err := NewFetcher().GetGroup(uris)
	if err != nil {
		return fmt.Errorf("fetching remote data: %w", err)
	}

	// Store the retrieved data in the resource descriptor
	for i, datum := range data {
		// Here we shoud validate any hashes we have
		newRefs[i].Location.Content = datum

		// Store the reference
		if err := store.StoreReference(newRefs[i]); err != nil {
			return fmt.Errorf("storing external ref #%d: %w", i, err)
		}
	}
	return nil
}

// FetchRemoteResources pulls all the remote data in parallel and stores it
// in the configured StorageBackend.
func (dci *defaultCompilerImpl) FetchRemoteResources(opts *CompilerOptions, store StorageBackend, refs []*api.PolicyRef) error {
	if store == nil {
		return errors.New("storage backend missing")
	}

	return fetchRemoteResources(opts, 0, store, refs)
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

		// index the tenet overlays:
		patches := map[string]*api.Tenet{}
		appenders := []*api.Tenet{}
		for _, t := range p.Tenets {
			// Tenets without ID (or, later, with IDs not matching the source policy)
			// will be added as new tenets to the policy. Only if IDs match on the
			// source and the overlay will be combined.
			if t.GetId() == "" {
				appenders = append(appenders, t)
				continue
			}
			patches[t.GetId()] = t
		}

		// Merge the local policy changes onto the remote:
		tenets := []*api.Tenet{}
		overlaysAdded := []string{}
		for _, t := range assembledPolicy.GetTenets() {
			nt, ok := proto.Clone(t).(*api.Tenet)
			if !ok {
				continue
			}
			if _, ok := patches[nt.GetId()]; nt.GetId() != "" && ok {
				proto.Merge(nt, patches[nt.GetId()])
			}
			overlaysAdded = append(overlaysAdded, nt.GetId())
			tenets = append(tenets, nt)
		}
		for id, t := range patches {
			if !slices.Contains(overlaysAdded, id) {
				tenets = append(tenets, t)
			}
		}
		tenets = append(tenets, appenders...)

		// Merge the policy overlay onto the remote policy
		proto.Merge(assembledPolicy, p)
		assembledPolicy.Tenets = tenets
		assembledPolicy.Source = nil

		// Now replace the local in the policy set with the enriched remote
		set.Policies[i] = assembledPolicy
	}
	if set.GetCommon() == nil {
		set.Common = &api.PolicySetCommon{}
	} else {
		set.GetCommon().References = nil
	}
	return nil
}

func (dci *defaultCompilerImpl) ValidateAssebledSet(*CompilerOptions, *api.PolicySet) error {
	return nil
}
