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

// type Subject struct {
// 	gointoto.ResourceDescriptor
// }

type Statement struct {
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

func (s *Statement) Type() attestation.Type {
	return gointoto.StatementTypeUri
}

// GetSubjects returns the statement's subjects
func (s *Statement) GetSubjects() []attestation.Subject {
	var ret = []attestation.Subject{}
	for i := range s.Subject {
		ret = append(ret, s.Subject[i])
	}
	return ret
}
