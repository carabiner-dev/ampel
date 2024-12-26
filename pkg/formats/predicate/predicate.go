package predicate

import (
	"errors"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/json"
)

type Format string

const (
	FormatJSON Format = "json"
)

type ParsersList map[Format]attestation.PredicateParser

// Parsers
var Parsers = ParsersList{}

func (pl *ParsersList) Parse(data []byte) (attestation.Predicate, error) {
	var errs = []error{}
	for _, p := range *pl {
		pred, err := p.Parse(data)
		if err == nil {
			return pred, nil
		}

		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Finally try the vanilla parser
	p := &json.Parser{}
	pred, err := p.Parse(data)
	if err != nil {
		return nil, err
	}
	return pred, nil
}
