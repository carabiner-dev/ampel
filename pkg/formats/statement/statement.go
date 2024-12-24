package statement

import (
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
)

type Format string

const (
	FormatInToto Format = "intoto"
)

// Parsers
var Parsers = map[Format]attestation.StatementParser{
	FormatInToto: intoto.Parser{},
}
