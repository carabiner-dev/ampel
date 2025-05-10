// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// fetchedRef abstracts a fetched policy reference with some indexed properties
type fetchedRef struct {
	Data      *[]byte
	Policies  []string
	Digests   map[string]string
	Policy    *v1.Policy
	PolicySet *v1.PolicySet
}

// Storage backend is an interface that fronts systems that store and index policies
type StorageBackend interface {
	StoreReference(*v1.PolicyRef) error
	GetReferencedPolicy(*v1.PolicyRef) (*v1.Policy, error)
}

func newRefStore() *refStore {
	return &refStore{
		references: map[string]*v1.PolicyRef{},
		policySets: map[string]*v1.PolicySet{},
		policies:   map[string]*v1.Policy{},
		ids:        map[string]string{},
		urls:       map[string]string{},
		hashes:     map[string]string{},
	}
}

type refStore struct {
	references map[string]*v1.PolicyRef
	policySets map[string]*v1.PolicySet
	policies   map[string]*v1.Policy
	ids        map[string]string
	urls       map[string]string
	hashes     map[string]string
}

// StoreReference stores a reference and adds it to the index
func (rs *refStore) StoreReference(ref *v1.PolicyRef) error {
	if ref.GetLocation() == nil {
		return fmt.Errorf("unable to store policy no location data found")
	}

	// If the policy content is nil at some point we could try to fetch it
	// but for now we use the fetcher as it it can fet in parallel.
	if ref.GetLocation().GetContent() == nil {
		return fmt.Errorf("unable to store policy, content is empty")
	}

	if ref.GetLocation().GetDigest() == nil {
		ref.GetLocation().Digest = map[string]string{}
	}

	// Hash the policy contents, this will be the main storage key
	h := sha256.New()
	h.Write(ref.GetLocation().GetContent())

	contentHash := fmt.Sprintf("%x", h.Sum(nil))

	// If the ref is missing its sha256 digest, generate it
	if _, ok := ref.GetLocation().GetDigest()[string(intoto.AlgorithmSHA256)]; !ok {
		ref.GetLocation().GetDigest()[string(intoto.AlgorithmSHA256)] = contentHash
	} else {
		if contentHash != ref.GetLocation().GetDigest()[string(intoto.AlgorithmSHA256)] {
			return fmt.Errorf("policy sha256 digest does not match content")
		}
	}

	// TODO(puerco) Here the reference shuold be augmented if it already exists
	rs.references[contentHash] = ref

	uri := ref.GetLocation().GetDownloadLocation()
	if uri == "" {
		uri = ref.GetLocation().GetUri()
	}
	if uri != "" {
		rs.urls[uri] = contentHash
	}

	for algo, val := range ref.GetLocation().GetDigest() {
		rs.hashes[fmt.Sprintf("%s:%s", algo, val)] = contentHash
	}

	// Parse the policyset
	set := &v1.PolicySet{}
	pol := &v1.Policy{}
	if err := protojson.Unmarshal(ref.Location.GetContent(), set); err == nil {
		rs.registerPolicySet(contentHash, set)
	} else if err := protojson.Unmarshal(ref.Location.GetContent(), pol); err == nil {
		rs.registerPolicy(contentHash, pol)
	} else {
		return errors.New("error parsing referenced content")
	}

	return nil
}

func (rs *refStore) registerPolicy(contentHash string, pol *v1.Policy) {
	rs.policies[contentHash] = pol
}

func (rs *refStore) registerPolicySet(contentHash string, set *v1.PolicySet) {
	// TODO(puerco): Aqui solo si es un set, si es policy no
	rs.policySets[contentHash] = set

	// TODO(puerco): Aqui solo si es un set
	// Store all the policy IDs in the referenced set
	for _, p := range set.GetPolicies() {
		if p.GetId() == "" {
			continue
		}
		rs.ids[p.GetId()] = contentHash
	}
}

// This retrieves a policy from the sets by its ID
func (rs *refStore) GetPolicyByID(id string) *v1.Policy {
	if sha, ok := rs.ids[id]; ok {
		for _, p := range rs.policySets[sha].GetPolicies() {
			if p.GetId() == id {
				return p
			}
		}
	}
	return nil
}

func (rs *refStore) GetPolicyRefBySHA256(sha string) *v1.PolicyRef {
	if v, ok := rs.references[sha]; ok {
		return v
	}
	return nil
}

func (rs *refStore) GetPolicySetBySHA256(sha string) *v1.PolicySet {
	sha = strings.TrimPrefix(sha, "sha256:")
	if v, ok := rs.policySets[sha]; ok {
		return v
	}
	return nil
}

// GetReferencedPolicy
func (rs *refStore) GetReferencedPolicy(ref *v1.PolicyRef) (*v1.Policy, error) {
	if ref.GetId() == "" {
		return nil, fmt.Errorf("reference does not have a policy ID")
	}

	// Try by ID
	if p := rs.GetPolicyByID(ref.GetId()); p != nil {
		return p, nil
	}

	// Can't locate it through any other means
	return nil, nil
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
		return nil, errors.New("unable to look up policy without id")
	}
	for e := range *ps {
		if !slices.Contains((*ps)[e].Policies, ref.GetId()) {
			continue
		}

		// If we already saw another policy with the same ID, then throw an err
		if pol != nil {
			return nil, fmt.Errorf("ambigous data: more than one policy found with id %s", ref.GetId())
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
