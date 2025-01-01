package intoto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate"
)

type Parser struct{}

func (p *Parser) Parse(b []byte) (attestation.Statement, error) {
	stmt := Statement{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	// Decode the statement data
	if err := dec.Decode(&stmt); err != nil {
		if strings.Contains(err.Error(), "json: unknown field ") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("decoding statement json: %w", err)
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
