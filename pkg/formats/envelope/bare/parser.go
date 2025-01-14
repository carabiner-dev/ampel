// Package bare implenta a parser to make non-signed attestations
// compatible with the ampel policy engine.
package bare

import (
	"errors"
	"fmt"
	"io"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/predicate"
	"github.com/puerco/ampel/pkg/formats/statement"
	"github.com/puerco/ampel/pkg/formats/statement/intoto"
	"github.com/sirupsen/logrus"
)

type Parser struct{}

// ParseStream reads an open stream and returns a parsed envelope
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	env := &Envelope{}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading input data: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("short read when parsing attestation source")
	}

	// When dealing with bare attestations, we can expect any JSON so we synthesize
	// an attestation and we will create a known predicate for it EXCEPT when the
	// json data is an attestation.
	s, err := statement.Parsers.Parse(data)
	if err == nil {
		logrus.Infof("founda statement %+v", s)
		env.Statement = s
		return []attestation.Envelope{env}, nil
	}

	if err != nil && !errors.Is(err, attestation.ErrNotCorrectFormat) {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	// OK, the reader does not contain a known statement type. So, to synthesize
	// our attestation, first we parse the data as a predicate
	pred, err := predicate.Parsers.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	// Asign the new statement
	s = intoto.NewStatement(intoto.WithPredicate(pred))
	env.Statement = s
	return []attestation.Envelope{env}, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json", "jsonl"}
}
