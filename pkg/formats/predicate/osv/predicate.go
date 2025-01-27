// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	protoOSV "github.com/carabiner-dev/osv/go/osv"
	"github.com/puerco/ampel/pkg/attestation"
)

var PredicateType = attestation.PredicateType("https://ossf.github.io/osv-schema/results@v1.6.7")

type Predicate struct {
	Parsed *protoOSV.Results
	Data   []byte
}

func (*Predicate) GetType() attestation.PredicateType {
	return PredicateType
}

func (p *Predicate) GetData() []byte {
	return p.Data
}

func (p *Predicate) GetParsed() any {
	return p.Parsed
}
