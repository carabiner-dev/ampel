package protobom

import (
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/puerco/ampel/pkg/attestation"
)

const PredicateType attestation.PredicateType = "application/protobom"

type Predicate struct {
	Data   []byte
	Parsed *sbom.Document
}

func (_ *Predicate) GetType() attestation.PredicateType {
	return PredicateType
}

func (p *Predicate) GetData() []byte {
	return p.Data
}
