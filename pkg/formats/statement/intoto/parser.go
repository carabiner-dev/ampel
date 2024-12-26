package intoto

import (
	"encoding/json"
	"fmt"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate"
)

type Parser struct{}

func (p *Parser) Parse(b []byte) (attestation.Statement, error) {
	stmt := Statement{}
	if err := json.Unmarshal(b, &stmt); err != nil {
		return nil, err
	}
	pdata, err := stmt.Statement.Predicate.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate data to JSON: %w", err)
	}
	pred, err := predicate.Parsers.Parse(pdata)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	stmt.Predicate = pred

	return &stmt, nil
}
