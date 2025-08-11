package policy

import (
	"fmt"
	"io"
	"os"

	v1 "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/carabiner-dev/ampel/pkg/policy/options"
	"github.com/carabiner-dev/signer"
	"google.golang.org/protobuf/encoding/protojson"
)

type PolicySigner struct{}

// func (ps *PolicySigner) Sign(*api.Policy)

// SignPolicyData signs raw policy data
func (ps *PolicySigner) SignPolicyData(data []byte, w io.Writer, funcs ...options.SignerOptFn) error {
	set, pcy, err := NewParser().ParsePolicyOrSet(data)
	if err != nil {
		return fmt.Errorf("parsing policy material: %w", err)
	}

	// Assemble the in-toto wrapper
	var statement *intoto.Statement
	material := PolicyOrSet(set, pcy)
	switch m := material.(type) {
	case *v1.PolicySet:
		statement = intoto.NewStatement(
			intoto.WithPredicate(m),
		)
	case *v1.Policy:
		statement = intoto.NewStatement(
			intoto.WithPredicate(m),
		)
	}

	// OK, data is valid, sign it.
	s := signer.NewSigner()

	bundle, err := s.SignBundle(data)
	if err != nil {
		return fmt.Errorf("signing policy material: %w", err)
	}

	jsonData, err := protojson.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshaling signed policy: %w", err)
	}

	if _, err := w.Write(jsonData); err != nil {
		return fmt.Errorf("writing JSON data to writer: %w", err)
	}
	return nil
}

// SignBundleToFile signs a policy file and writes it to a filename derived from the original.
func (ps *PolicySigner) SignPolicyFile(path string, w io.Writer, funcs ...options.SignerOptFn) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading policy data: %w", err)
	}

	return ps.SignPolicyData(data, w, funcs...)
}
