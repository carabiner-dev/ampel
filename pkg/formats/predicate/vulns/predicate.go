package vulns

import (
	v01 "github.com/in-toto/attestation/go/predicates/vulns/v01"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/puerco/ampel/pkg/attestation"
)

type predicate struct {
	Type   attestation.PredicateType
	Parsed any
	Data   []byte
}

func (p *predicate) GetData() []byte {
	return p.Data
}

func (p *predicate) GetParsed() any {
	return p.Parsed
}

func (p *predicate) GetType() attestation.PredicateType {
	return p.Type
}

type PredicateV1 struct {
	predicate
	Parsed *v01.Vulns
}

type PredicateV2 struct {
	predicate
	Parsed *v02.Vulns
}
