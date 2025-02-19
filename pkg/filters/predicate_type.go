// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filters

import "github.com/carabiner-dev/ampel/pkg/attestation"

type PredicateTypeMatcher struct {
	PredicateTypes map[attestation.PredicateType]struct{}
}

func (ptm *PredicateTypeMatcher) Matches(att attestation.Envelope) bool {
	if att.GetStatement() == nil {
		return false
	}

	if _, ok := ptm.PredicateTypes[att.GetStatement().GetPredicateType()]; ok {
		return true
	}

	return false
}
