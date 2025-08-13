// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/carabiner-dev/attestation"
)

type Cache interface {
	StoreAttestationsByPredicateType(context.Context, []attestation.PredicateType, *[]attestation.Envelope) error
	GetAttestationsByPredicateType(context.Context, []attestation.PredicateType) (*[]attestation.Envelope, error)
	StoreAttestationsBySubject(context.Context, []attestation.Subject, *[]attestation.Envelope) error
	GetAttestationsBySubject(context.Context, []attestation.Subject) (*[]attestation.Envelope, error)
}

// Ensure the memcache implements the cache interface
var _ Cache = (*MemoryCache)(nil)

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		predicateType: map[string]*[]attestation.Envelope{},
		subject:       map[string]*[]attestation.Envelope{},
		times:         map[string]time.Time{},
	}
}

type MemoryCache struct {
	predicateType map[string]*[]attestation.Envelope
	subject       map[string]*[]attestation.Envelope
	times         map[string]time.Time
}

func buildKey[T ~string](getters []T) string {
	keys := make([]string, len(getters))
	for i, s := range getters {
		keys[i] = string(s)
	}
	slices.Sort(keys)
	return strings.Join(keys, ":")
}

func (memcache *MemoryCache) StoreAttestationsByPredicateType(ctx context.Context, pt []attestation.PredicateType, atts *[]attestation.Envelope) error {
	k := buildKey(pt)
	memcache.predicateType[k] = atts
	memcache.times[k] = time.Now()
	return nil
}

func (memcache *MemoryCache) GetAttestationsByPredicateType(ctx context.Context, pt []attestation.PredicateType) (*[]attestation.Envelope, error) {
	if v, ok := memcache.predicateType[buildKey(pt)]; ok {
		return v, nil
	}
	return nil, nil
}

func subjectToKey(s attestation.Subject) string {
	ret := ""
	if s.GetName() != "" {
		ret += s.GetName() + "-"
	}
	if s.GetUri() != "" {
		ret += s.GetUri() + "-"
	}
	for algo, val := range s.GetDigest() {
		ret += fmt.Sprintf("%s:%s", algo, val) + "-"
	}
	return ret
}

func (memcache *MemoryCache) StoreAttestationsBySubject(ctx context.Context, subjects []attestation.Subject, atts *[]attestation.Envelope) error {
	keys := []string{}
	for _, subject := range subjects {
		keys = append(keys, subjectToKey(subject))
	}
	k := buildKey(keys)
	memcache.subject[k] = atts
	memcache.times[k] = time.Now()

	return nil
}

func (memcache *MemoryCache) GetAttestationsBySubject(ctx context.Context, subjects []attestation.Subject) (*[]attestation.Envelope, error) {
	keys := []string{}
	for _, subject := range subjects {
		keys = append(keys, subjectToKey(subject))
	}
	k := buildKey(keys)
	if v, ok := memcache.subject[k]; ok {
		return v, nil
	}
	return nil, nil
}
