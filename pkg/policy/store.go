// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
)

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
	} else if contentHash != ref.GetLocation().GetDigest()[string(intoto.AlgorithmSHA256)] {
		return fmt.Errorf("policy sha256 digest does not match content")
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
	if id == "" {
		return nil
	}
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
	// Try finding the policy by indexed ID
	if p := rs.GetPolicyByID(ref.GetId()); p != nil {
		return p, nil
	}

	// Can't locate it through any other means
	return nil, nil
}

// This error is thrown if a fetchedRef lists a policy ID not
// contained in its policy or policy set. If it's ever thrown
// it is definitely a bug:
var ErrParseInconsistency = errors.New("internal error: fetched reference ID and policy ID mismatch")
