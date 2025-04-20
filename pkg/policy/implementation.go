// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"strings"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
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
	for i, p := range set.Policies {
		// If the policy has no source, it's inline. Skip
		if p.GetSource() == nil || p.GetSource().GetLocation() == nil {
			continue
		}

		// Only fetch the blobs we don't already have
		needToParse := false
		for algo, val := range p.GetSource().GetLocation().GetDigest() {
			if _, ok := (*store)[fmt.Sprintf("%s:%s", algo, val)]; !ok {
				needToParse = true
				break
			}
		}
		if !needToParse {
			logrus.Infof("Already have remote policy data")
			continue
		}

		// Check if the policy has a DownloadLocation
		url := p.GetSource().GetLocation().GetDownloadLocation()
		if url == "" {
			url = p.GetSource().GetLocation().GetUri()
		}

		if url == "" {
			return nil, fmt.Errorf("policy reference #%d has not url to fetch", i)
		}
		logrus.Infof("fetching remote policy data from %s", url)
		data, err := fetcher.Get(url)
		if err != nil {
			return nil, fmt.Errorf("fetching policy reference: %w", err)
		}

		fr, err := parseFetchedRef(data)
		if err != nil {
			return nil, fmt.Errorf("parsing remote data: %w", err)
		}

		for algo, val := range p.GetSource().GetLocation().GetDigest() {
			// FIXME: Validate the hashes before storing
			(*store)[fmt.Sprintf("%s:%s", algo, val)] = *fr
		}
	}
	return store, nil
}

// parseFetchedRef reads data and returns a fetchedRef with the
// parsed policy or policy set. If the data is not a policy or policyset
// or invalid json, then an error is thrown.
func parseFetchedRef(data []byte) (*fetchedRef, error) {
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}

	policySingle := &v1.Policy{}
	policySet := &v1.PolicySet{}

	if err := unmarshaler.Unmarshal(data, policySingle); err != nil {
		if !strings.Contains(err.Error(), "unknown field") {
			return nil, fmt.Errorf("unmarshaling Policy: %w", err)
		}
		policySingle = nil
	}

	if err := unmarshaler.Unmarshal(data, policySet); err != nil {
		if !strings.Contains(err.Error(), "unknown field") {
			return nil, fmt.Errorf("unmarshaling PolicySet: %w", err)
		}
		policySet = nil
	}

	if policySet == nil && policySingle == nil {
		return nil, fmt.Errorf("data is not an AMPEL Policy or PolicySet")
	}

	return &fetchedRef{
		Data:      &data,
		Policy:    policySingle,
		PolicySet: policySet,
	}, nil
}

// CompletePolicySet
func (dpi *defaultParserImplementation) CompletePolicySet(set *v1.PolicySet, store *policyStore) error {
LOOP:
	for i, p := range set.Policies {
		// If the policy does not hava remote source, skip
		if p.Source == nil {
			continue
		}

		// Keep the original source to restick it
		ref := p.Source
		// Now retrieve the fetched policies through the hashed blobs
		for algo, val := range p.GetSource().GetLocation().GetDigest() {
			if fr, ok := (*store)[fmt.Sprintf("%s:%s", algo, val)]; ok {
				logrus.Infof("Building %s from %s:%s", p.Id, algo, val)
				if fr.Policy != nil {
					if p.GetSource().GetId() == "" {
						p = fr.Policy
						p.Source = ref
						continue LOOP
					}
					if fr.Policy.GetId() == p.GetSource().GetId() {
						// Policy is here
						p = fr.Policy
						p.Source = ref
						continue LOOP
					} else {
						return fmt.Errorf("referenced policy ID does not match source definition #%d", i)
					}
				}

				if fr.PolicySet != nil {
					// If the source points to a policy set, we require an
					// ID to pick the policy out of the set.
					if p.GetSource().GetId() == "" {
						return fmt.Errorf("policy #%d points to a remote PolicySet but has no ID", i)
					}
					for _, remotePolicy := range fr.PolicySet.GetPolicies() {
						if remotePolicy.GetId() == p.GetSource().GetId() {
							set.Policies[i] = remotePolicy
							set.Policies[i].Source = ref
							logrus.Infof("FOUND %+v", set.Policies[i])

							continue LOOP
						}
					}
				}
			}
		}
		return fmt.Errorf("unable to complete policy #%d", i)
	}
	return nil
}
