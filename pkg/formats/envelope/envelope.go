package envelope

import (
	"io"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/envelope/bare"
	"github.com/puerco/ampel/pkg/formats/envelope/dsse"
)

type Format string

const (
	FormatDSSE Format = "dsse"
	FormatBare Format = "bare"
)

// ParserList wraps a map listing the loaded parsers to expose convenience methods
type ParserList map[Format]attestation.EnvelopeParser

var Parsers = ParserList{
	FormatDSSE: &dsse.Parser{},
	FormatBare: &bare.Parser{},
}

// Parse takes a reader and parses
func (list *ParserList) Parse(r io.Reader) ([]attestation.Envelope, error) {
	return nil, nil
}
