package osv

import (
	"github.com/puerco/ampel/pkg/attestation"
	protoOSV "github.com/puerco/ampel/pkg/osv"
)

var PredicateType = attestation.PredicateType("https://ossf.github.io/osv-schema/v1.6.7")

type Predicate struct {
	Parsed *protoOSV.Predicate
	Data   []byte
}

func (*Predicate) GetType() attestation.PredicateType {
	return PredicateType
}

func (p *Predicate) GetData() []byte {
	return p.Data
}

func (p *Predicate) GetParsed() any {
	return p.Parsed
}
