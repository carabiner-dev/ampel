// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulns

import (
	v01 "github.com/in-toto/attestation/go/predicates/vulns/v01"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/puerco/ampel/pkg/attestation"
)

var PredicateTypeV2 = attestation.PredicateType("https://in-toto.io/attestation/vulns/v0.2")
var PredicateType = PredicateTypeV2

type predicate struct {
	Type   attestation.PredicateType
	Parsed any
	Data   []byte
}

func (p *predicate) GetData() []byte {
	return p.Data
}

func (p *predicate) GetParsed() any {
	return p.Parsed
}

func (p *predicate) GetType() attestation.PredicateType {
	return p.Type
}

type PredicateV1 struct {
	predicate
	Parsed *v01.Vulns
}

type PredicateV2 struct {
	predicate
	Parsed *v02.Vulns
}
