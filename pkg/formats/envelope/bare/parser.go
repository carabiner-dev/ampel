// Package bare implenta a parser to make non-signed attestations
// compatible with the ampel policy engine.
package bare

import (
	"fmt"
	"io"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/formats/statement"
)

type Parser struct{}

// ParseStream reads an open stream and returns a parsed envelope
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	env := &Envelope{}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading input data: %w", err)
	}

	// Parse the predicate
	s, err := statement.Parsers.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}
	env.Statement = s
	return []attestation.Envelope{env}, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json", "jsonl"}
}
