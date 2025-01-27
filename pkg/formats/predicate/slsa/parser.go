package slsa

import (
	"fmt"
	"strings"

	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
)

type Parser struct{}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var provenance = v1.Provenance{}
	if err := protojson.Unmarshal(data, &provenance); err != nil {
		// Transform the error to our wrong type error
		if strings.Contains(err.Error(), "proto:") &&
			strings.Contains(err.Error(), "syntax error") &&
			strings.Contains(err.Error(), "invalid value") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("error parsing v02 vuln predicate: %s", err)
	}
	return &Predicate{
		Type:   PredicateType,
		Parsed: &provenance,
		Data:   data,
	}, nil
}
