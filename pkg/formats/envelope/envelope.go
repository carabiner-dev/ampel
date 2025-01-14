package envelope

import (
	"errors"
	"io"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/envelope/bare"
	"github.com/puerco/ampel/pkg/formats/envelope/dsse"
	"github.com/sirupsen/logrus"
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
	for f, parser := range *list {
		logrus.Debugf("Checking if envelope is %s", f)
		env, err := parser.ParseStream(r)
		if err == nil {
			logrus.Infof("Found %s envelope", f)
			return env, nil
		}
		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			return nil, err
		}
	}
	return nil, attestation.ErrNotCorrectFormat
}
