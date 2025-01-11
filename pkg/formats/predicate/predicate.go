package predicate

import (
	"errors"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate/json"
	"github.com/puerco/ampel/pkg/formats/predicate/protobom"
)

type ParsersList map[attestation.PredicateType]attestation.PredicateParser

// Parsers
var Parsers = ParsersList{
	protobom.PredicateType: protobom.New(),
}

type Options struct {
	TypeHints []string
}

func (pl *ParsersList) Parse(data []byte) (attestation.Predicate, error) {
	var errs = []error{}
	for _, p := range *pl {
		pred, err := p.Parse(data)
		if err == nil {
			return pred, nil
		}

		// If we have predicate type hints, check if the parser can handle them
		if !p.SupportsType() {
			continue
		}

		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Finally try the vanilla JSON parser
	p := &json.Parser{}
	pred, err := p.Parse(data)
	if err != nil {
		return nil, err
	}
	return pred, nil
}
