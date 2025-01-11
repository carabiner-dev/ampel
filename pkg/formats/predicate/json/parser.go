package json

import (
	gojson "encoding/json"
	"fmt"

	"github.com/puerco/ampel/pkg/attestation"
)

type Parser struct{}

// Ensure this parser implements the interface
var _ attestation.PredicateParser = (*Parser)(nil)

// Parse generates a generic JSON predicate object from any JSON it gets.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	pred := &Predicate{
		Data: data,
	}
	parsedData := DataMap{}
	if err := gojson.Unmarshal(pred.Data, &parsedData); err != nil {
		return nil, fmt.Errorf("parsing json data: %w", err)
	}
	pred.Parsed = parsedData
	return pred, nil
}

// SupportsType always returns true because the json parser
// is a catchall predicate parser.
func (p *Parser) SupportsType(testTypes ...string) bool {
	return true
}
