// Package json implements a "catch-all" predicate type that is just
// an unmarshaled json blob

package json

import "github.com/puerco/ampel/pkg/attestation"

const PredicateType attestation.PredicateType = "text/json"

var _ attestation.Predicate = (*Predicate)(nil)

type DataMap map[string]any

// Predicate is a generic JSON predicate type for all unknown JSON
type Predicate struct {
	Type   attestation.PredicateType
	Data   []byte
	Parsed DataMap
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
