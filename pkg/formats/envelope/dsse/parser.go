package dsse

import (
	"io"

	"github.com/puerco/ampel/pkg/attestation"
)

// EnvelopeParser

type Parser struct {
}

// ParseFile parses a file and returns all envelopes in it.
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	return nil, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json", "jsonl", "intoto"}
}
