package openeox

import "github.com/puerco/ampel/pkg/attestation"

var PredicateType = attestation.PredicateType("https://openeox.org/schema-0.2.0.json")

// Predicate is the OpenEoX predicate type
type Predicate struct {
	Type   attestation.PredicateType
	Parsed *EOX
	Data   []byte
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
