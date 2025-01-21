package vulns

import (
	"fmt"

	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/puerco/ampel/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
)

// Parser is the vulnerability parser
type Parser struct{}

func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	// Try v02 and then v01
	var pred attestation.Predicate
	pred, err := parseV2(data)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	return pred, nil
}

func parseV2(data []byte) (*PredicateV2, error) {
	v2 := v02.Vulns{}
	if err := protojson.Unmarshal(data, &v2); err != nil {
		return nil, fmt.Errorf("error parsing v02 vuln predicate: %s", err)
	}
	pred := &PredicateV2{
		Parsed: &v2,
	}
	return pred, nil
}
