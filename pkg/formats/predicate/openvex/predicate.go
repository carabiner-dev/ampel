package openvex

import (
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/puerco/ampel/pkg/attestation"
)

type Predicate struct {
	Type   attestation.PredicateType
	Data   []byte
	Parsed *openvex.VEX
}

func (p *Predicate) GetType() attestation.PredicateType {
	if p.Type == "" {
		return PredicateType
	}
	return p.Type
}

func (p *Predicate) GetData() []byte {
	return p.Data
}

func (p *Predicate) GetParsed() any {
	return p.Parsed
}
