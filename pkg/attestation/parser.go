package attestation

import (
	"errors"
	"io"
)

var ErrNotCorrectFormat = errors.New("data does not conform to parser's format")

type EnvelopeParser interface {
	ParseStream(r io.Reader) ([]Envelope, error)
	FileExtensions() []string
}

type StatementParser interface {
	Parse([]byte) (Statement, error)
}

type PredicateParser interface {
	Parse([]byte) (Predicate, error)
	SupportsType(...string) bool
}
