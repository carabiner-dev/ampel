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

type OptionFunc func(*Predicate) error

func WithJson(data []byte) OptionFunc {
	return func(pred *Predicate) error {
		// Parse into a generica structure
		var parsed = DataMap{}
		if err := gojson.Unmarshal(data, &parsed); err != nil {
			return fmt.Errorf("parsing predicate json: %w", err)
		}

		pred.Data = data
		pred.Parsed = parsed
		return nil
	}
}

func WithType(pt attestation.PredicateType) OptionFunc {
	return func(pred *Predicate) error {
		pred.Type = pt
		return nil
	}
}

func New(optsFn ...OptionFunc) (*Predicate, error) {
	var pred = &Predicate{
		Type: PredicateType,
	}
	for _, of := range optsFn {
		if err := of(pred); err != nil {
			return nil, err
		}
	}
	return pred, nil
}
