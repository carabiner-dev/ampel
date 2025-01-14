package transformer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/transformer/protobom"
	"github.com/sirupsen/logrus"
)

// Ensure this parser implements the interface
var _ Transformer = (*protobom.Transformer)(nil)

type Class string

func (c *Class) Version() string {
	_, a, _ := strings.Cut(string(*c), "/")
	return a
}

func (c *Class) Name() string {
	b, _, _ := strings.Cut(string(*c), "/")
	return b
}

// Factory returns a list of transformers from
// a list of string identifiers
type Factory struct {
}

// Get returns
func (tf *Factory) Get(c Class) (Transformer, error) {
	if !strings.HasPrefix(c.Name(), "internal:") {
		return nil, errors.New("only internal transformers are supported for now")
	}

	s := strings.TrimPrefix(c.Name(), "internal:")
	switch s {
	case protobom.ClassName:
		logrus.Debugf("Found driver for transformer transformer class %s", s)
		return protobom.New(), nil
	default:
		return nil, fmt.Errorf("unknown transformer %q", s)
	}
}

// Transformer is an interface that models a predicate transformer
type Transformer interface {
	Default([]attestation.Predicate) ([]attestation.Predicate, error)
}

type Info struct {
	Identifier string
	Version    string
	Hashes     map[string]string
}

// InputRecord records the inputs that went into a predicate
// transformation process.
type InputRecord struct {
	Type     attestation.PredicateType
	Subjects []attestation.Subject
	Hashes   map[string]string
}

// OutputRecord is a struct that catpures metadata about
// the outputs resulting from a tranformer run.
type OutputRecord struct {
	Hashes map[string]string
	Type   attestation.PredicateType
}

// Record is a struct that records a run
// of a transformer.
type Record struct {
	Date        *time.Time
	Transformer Info
	Inputs      []InputRecord
	Output      []OutputRecord
}
