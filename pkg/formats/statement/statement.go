package statement

import (
	"errors"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
)

type Format string

const (
	FormatInToto Format = "intoto"
)

type ParserList map[Format]attestation.StatementParser

// Parsers
var Parsers = ParserList{
	FormatInToto: &intoto.Parser{},
}

// Parse
func (pl *ParserList) Parse(data []byte) (attestation.Statement, error) {
	var errs = []error{}
	for _, p := range *pl {
		pres, err := p.Parse(data)
		if err == nil {
			return pres, nil
		}
		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		// no suitabkle parser
	}
	return nil, errors.Join(errs...)
}
