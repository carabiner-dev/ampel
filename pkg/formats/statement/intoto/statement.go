// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package intoto implements a parser and a statement variant for
// attestations in the in-toto format.
package intoto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	gointoto "github.com/in-toto/attestation/go/v1"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate"
)

// var _ attestation.Subject = (*Subject)(nil)
type StatementOption func(*Statement)

func WithPredicate(pred attestation.Predicate) StatementOption {
	return func(stmnt *Statement) {
		stmnt.Predicate = pred
		stmnt.PredicateType = pred.GetType()
	}
}

func WithSubject(subjects ...*gointoto.ResourceDescriptor) StatementOption {
	return func(stmnt *Statement) {
		stmnt.Subject = append(stmnt.Subject, subjects...)
	}
}

func NewStatement(opts ...StatementOption) *Statement {
	s := &Statement{
		Predicate: nil,
		Statement: gointoto.Statement{
			Type: gointoto.StatementTypeUri,
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

type Statement struct {
	PredicateType attestation.PredicateType `json:"predicateType"`
	Predicate     attestation.Predicate     `json:"predicate"`
	gointoto.Statement
}

func (s *Statement) AddSubject(sbj attestation.Subject) {
	descr := gointoto.ResourceDescriptor{
		Name:   sbj.GetName(),
		Uri:    sbj.GetUri(),
		Digest: sbj.GetDigest(),
	}
	s.Subject = append(s.Subject, &descr)
}

func (s *Statement) GetPredicate() attestation.Predicate {
	return s.Predicate
}

// ParsePredicate reparses the underlying intoto predicate and regenerates the
// statement's predicate.
func (s *Statement) ParsePredicate() error {
	pred, err := predicate.Parsers.Parse([]byte(s.Statement.Predicate.String()))
	if err != nil {
		return fmt.Errorf("parsing predicate: %w", err)
	}

	s.Predicate = pred
	return nil
}

// GetSubjects returns the statement's subjects
func (s *Statement) GetSubjects() []attestation.Subject {
	ret := []attestation.Subject{}
	for i := range s.Subject {
		ret = append(ret, s.Subject[i])
	}
	return ret
}

func (s *Statement) GetPredicateType() attestation.PredicateType {
	return s.PredicateType
}

// ToJson returns a byte slice with the predicate in JSON
func (s *Statement) ToJson() ([]byte, error) {
	var b bytes.Buffer
	if err := s.WriteJson(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (s *Statement) WriteJson(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("writing JSON stream: %w", err)
	}
	return nil
}

// GetVerifications returns the verifications from the underlying predicate
func (s *Statement) GetVerification() *api.Verification {
	if s.GetPredicate() == nil {
		return nil
	}
	return s.GetPredicate().GetVerification()
}
