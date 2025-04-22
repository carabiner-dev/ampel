// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/carabiner-dev/hasher"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
)

type parserImplementation interface {
	ParsePolicySet([]byte) (*v1.PolicySet, error)
	FetchReferences(PolicyFetcher, *v1.PolicySet) (*policyStore, error)
	CompletePolicySet(*v1.PolicySet, *policyStore) error
}

type defaultParserImplementation struct{}

func (dpi *defaultParserImplementation) ParsePolicySet(policySetData []byte) (*v1.PolicySet, error) {
	set := &v1.PolicySet{}
	err := protojson.UnmarshalOptions{}.Unmarshal(policySetData, set)
	if err != nil {
		return nil, fmt.Errorf("parsing policy source: %w", err)
	}

	if set.GetMeta() == nil {
		set.Meta = &v1.PolicySetMeta{}
	}

	if set.GetMeta().GetEnforce() == "" {
		set.GetMeta().Enforce = EnforceOn
	}

	for _, p := range set.Policies {
		if p.GetMeta() == nil {
			p.Meta = &v1.Meta{}
		}

		if p.GetMeta().GetAssertMode() == "" {
			p.GetMeta().AssertMode = AssertModeAND
		}

		if p.GetMeta().GetEnforce() == "" {
			p.GetMeta().Enforce = EnforceOn
		}
	}
	return set, nil
}

// FetchReferences
func (dpi *defaultParserImplementation) FetchReferences(fetcher PolicyFetcher, set *v1.PolicySet) (*policyStore, error) {
	store := &policyStore{}
	// Fetch the PolicySet common references
	if set.GetReferences() != nil {
		for i, ref := range set.GetReferences() {
			if err := fetchRefIfNeeded(fetcher, store, ref); err != nil {
				return nil, fmt.Errorf("getting global policy reference #%d: %w", i, err)
			}
		}
	}

	// The fetch external references at the policy level
	for i, p := range set.Policies {
		// If the policy has no source, it's inline. Skip
		if p.GetSource() == nil || p.GetSource().GetLocation() == nil {
			continue
		}

		if err := fetchRefIfNeeded(fetcher, store, p.GetSource()); err != nil {
			return nil, fmt.Errorf("getting policy reference #%d: %w", i, err)
		}
	}
	return store, nil
}

func fetchRefIfNeeded(fetcher PolicyFetcher, store *policyStore, ref *v1.PolicyRef) error {
	if ref.GetLocation() == nil {
		// If there is no location, then noop
		return nil
	}
	// Only fetch the blobs we don't already have
	needToParse := false
	for algo, val := range ref.GetLocation().GetDigest() {
		if fr := store.GetFetchedRefByHash(algo, val); fr == nil {
			needToParse = true
			logrus.Infof("dont have data for %s:%s", algo, val)
			break
		}
	}
	if !needToParse {
		logrus.Infof("Already have remote policy data")
		return nil
	}

	// Check if the policy has a DownloadLocation
	url := ref.GetLocation().GetDownloadLocation()
	if url == "" {
		url = ref.GetLocation().GetUri()
	}

	if url == "" {
		return errors.New("policy reference has no url to fetch")
	}

	logrus.Infof("fetching remote policy data from %s", url)
	data, err := fetcher.Get(url)
	if err != nil {
		return fmt.Errorf("fetching policy reference: %w", err)
	}

	dataHash, fr, err := parseFetchedRef(data)
	if err != nil {
		return fmt.Errorf("parsing remote data: %w", err)
	}

	hshr := hasher.New()
	verified, err := hshr.VerifyReader(bytes.NewReader(data), hasher.NewHashSet(ref.GetLocation().GetDigest()))
	if err != nil {
		return fmt.Errorf("verifying data: %w", err)
	}

	if !verified {
		return fmt.Errorf("cannot validate referenced policy data with provided hashes")
	}

	fr.Digests = ref.GetLocation().GetDigest()

	// This can happen if the ref hash extra hashes not found
	// in the known artifact
	if _, ok := (*store)[dataHash]; ok {
		maps.Copy((*store)[dataHash].Digests, fr.Digests)
	} else {
		(*store)[dataHash] = fr
	}
	return nil
}

// parseFetchedRef reads data and returns a fetchedRef with the
// parsed policy or policy set. If the data is not a policy or policyset
// or invalid json, then an error is thrown.
func parseFetchedRef(data []byte) (string, *fetchedRef, error) {
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}

	// Compute the fetched data digest:
	hasher := sha256.New()
	if _, err := hasher.Write(data); err != nil {
		return "", nil, fmt.Errorf("hashing data: %w", err)
	}
	dataHash := fmt.Sprintf("%x", hasher.Sum(nil))

	policySingle := &v1.Policy{}
	policySet := &v1.PolicySet{}
	policies := []string{}

	if err := unmarshaler.Unmarshal(data, policySingle); err != nil {
		if !strings.Contains(err.Error(), "unknown field") {
			return dataHash, nil, fmt.Errorf("unmarshaling Policy: %w", err)
		}
		policySingle = nil
	}

	if err := unmarshaler.Unmarshal(data, policySet); err != nil {
		if !strings.Contains(err.Error(), "unknown field") {
			return dataHash, nil, fmt.Errorf("unmarshaling PolicySet: %w", err)
		}
		policySet = nil
	}

	if policySet == nil && policySingle == nil {
		return dataHash, nil, fmt.Errorf("data is not an AMPEL Policy or PolicySet")
	}

	if policySingle != nil && policySingle.GetId() != "" {
		policies = []string{policySingle.GetId()}
	}

	if policySet != nil {
		for _, p := range policySet.GetPolicies() {
			if p.GetId() == "" {
				continue
			}
			policies = append(policies, p.GetId())
		}
	}

	return dataHash, &fetchedRef{
		Data:      &data,
		Policy:    policySingle,
		PolicySet: policySet,
		Policies:  policies,
	}, nil
}

// CompletePolicySet
func (dpi *defaultParserImplementation) CompletePolicySet(set *v1.PolicySet, store *policyStore) error {
	for i, p := range set.Policies {
		// If the policy does not hava remote source, skip
		if p.Source == nil {
			continue
		}
		policy, err := store.GetReferencedPolicy(p.Source)
		if err != nil {
			return fmt.Errorf("getting referenced policy: %w", err)
		}

		if policy == nil {
			return fmt.Errorf("unable to complete policy #%d, reference nor resolved", i)
		}

		ref := p.Source // Keep the reference spec
		set.Policies[i] = policy
		set.Policies[i].Source = ref
	}
	return nil
}
