package attestation

import "io"

type EnvelopeParser interface {
	ParseStream(r io.Reader) ([]Envelope, error)
	FileExtensions() []string
}

type StatementParser interface {
}
