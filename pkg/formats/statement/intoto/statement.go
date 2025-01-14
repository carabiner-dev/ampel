// Package intoto implements a parser and a statement variant for
// attestations in the in-toto format.
package intoto

import (
	"fmt"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate"
)

// var _ attestation.Subject = (*Subject)(nil)
type StatementOption func(*Statement)

func WithPredicate(pred attestation.Predicate) StatementOption {
	return func(stmnt *Statement) {
		stmnt.Predicate = pred
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
	// Type      string `protobuf:"bytes,1,opt,name=type,json=_type,proto3" json:"type,omitempty"`
	Predicate attestation.Predicate
	gointoto.Statement
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
	var ret = []attestation.Subject{}
	for i := range s.Subject {
		ret = append(ret, s.Subject[i])
	}
	return ret
}

func (s *Statement) GetPredicateType() attestation.PredicateType {
	return s.Predicate.GetType()
}
