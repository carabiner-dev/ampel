// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"slices"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
)

// fetchedRef abstracts a fetched policy reference with some indexed properties
type fetchedRef struct {
	Data      *[]byte
	Policies  []string
	Digests   map[string]string
	Policy    *v1.Policy
	PolicySet *v1.PolicySet
}

// policyStore is a struct to hold the fetched remote policies
type policyStore map[string]*fetchedRef

// This error is thrown if a fetchedRef lists a policy ID not
// contained in its policy or policy set. If it's ever thrown
// it is definitely a bug:
var ErrParseInconsistency = errors.New("internal error: fetched reference ID and policy ID mismatch")

func (ps *policyStore) GetReferencedPolicy(ref *v1.PolicyRef) (*v1.Policy, error) {
	// If the reference specifies the source digest, lock it
	if ref.GetLocation() != nil && ref.GetLocation().GetDigest() != nil {
		return ps.GetReferencedPolicyByHash(ref)
	}

	// The other option is we look for a policy by id in the trusted
	// data we already ingested
	if ref.GetId() != "" {
		return ps.GetReferencedPolicyById(ref)
	}

	return nil, fmt.Errorf("unable to resolve external reference: no digests and or id found")
}

// GetReferencedPolicyById returns a referenced policy by looking up its
// id in the trusted remote data. To avoid ambiguity with policy IDs, the
// policy ID in the reference must be unique in all the ingested data or an
// error will be returned
func (ps *policyStore) GetReferencedPolicyById(ref *v1.PolicyRef) (*v1.Policy, error) {
	var pol *v1.Policy
	if ref.GetId() == "" {
		return nil, errors.New("cannot get by ID: reference has no ID set")
	}
	for e := range *ps {
		if !slices.Contains((*ps)[e].Policies, ref.GetId()) {
			continue
		}

		// If we already saw another policy with the same ID, then throw an err
		if pol != nil {
			return nil, fmt.Errorf("ambigous data: more thatn one policy found with id %s", ref.GetId())
		}

		// If it's a policy, got it
		if (*ps)[e].Policy != nil {
			pol = (*ps)[e].Policy
			continue
		}

		// or cycle the policy set policies
		for _, p := range (*ps)[e].PolicySet.GetPolicies() {
			if p.GetId() == ref.GetId() {
				pol = p
				break
			}
		}
	}
	return pol, nil
}

// GetReferencedPolicyByHash handles the case where a policy reference has hashes
// in its digest and possibly an ID.
func (ps *policyStore) GetReferencedPolicyByHash(ref *v1.PolicyRef) (*v1.Policy, error) {
	for algo, val := range ref.GetLocation().GetDigest() {
		// Hashes in ref match:
		fr := ps.GetFetchedRefByHash(algo, val)
		if fr == nil {
			continue
		}

		// Case 1: Only hashes match, we have no ID. If we have a policy that is it.
		if ref.GetId() == "" && fr.Policy != nil {
			return fr.Policy, nil
		}

		// Case 2: Hashes match and we have an ID. Then the policy ID
		// must match or if it's a set it needs to have a policy with that ID

		// ... first check if the fetchedReference has a matching policy ID.
		// Otherwise we can skip it now.
		if ref.GetId() != "" && !slices.Contains(fr.Policies, ref.GetId()) {
			continue
		}

		// Easiest, if the policy matches, we have it:
		if fr.Policy != nil && fr.Policy.GetId() == ref.GetId() {
			return fr.Policy, nil
		} else if fr.Policy != nil {
			// Here we have an inconsitency in parsing, so an error
			return nil, ErrParseInconsistency
		}

		// OK, at this point we know we are looking for a policy
		// in the policy set
		for _, p := range fr.PolicySet.GetPolicies() {
			if p.GetId() == ref.GetId() {
				return p, nil
			}
		}
		// same as above, if this happens we have an inconsistency error
		return nil, ErrParseInconsistency
	}

	return nil, nil
}

// GetFetchedRefByHash gets a hash and returns a fetchedReference if
// we have one that matches, else nil
func (ps *policyStore) GetFetchedRefByHash(algo, val string) *fetchedRef {
	for e := range *ps {
		if k, ok := (*ps)[e].Digests[algo]; ok {
			if k == val {
				return (*ps)[e]
			}
		}
	}
	return nil
}
