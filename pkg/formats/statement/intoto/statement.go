// Package intoto implements a parser and a statement variant for
// attestations in the in-toto format.
package intoto

import (
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/puerco/ampel/pkg/attestation"
)

var _ attestation.Subject = (*InTotoSubject)(nil)

type InTotoSubject struct {
	gointoto.ResourceDescriptor
}

func (its *InTotoSubject) GetURI() string {
	return its.GetURI()
}

type InToto struct {
	gointoto.Statement
}

type Parser struct{}
