// Package bare implenta a parser to make non-signed attestations
// compatible with the ampel policy engine.
package bare

import (
	"io"

	"github.com/puerco/ampel/pkg/attestation"
)

type Parser struct{}

func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	return nil, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json", "jsonl"}
}
