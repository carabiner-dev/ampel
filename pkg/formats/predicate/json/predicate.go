// Package json implements a "catch-all" predicate type that is just
// an unmarshaled json blob

package json

import "github.com/puerco/ampel/pkg/attestation"

var _ attestation.Predicate = (*Predicate)(nil)

type DataMap map[string]any

// Predicate is a generic JSON predicate type for all unknown JSON
type Predicate struct {
	Data   []byte
	Parsed DataMap
}
