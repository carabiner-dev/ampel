// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filters

import (
	"github.com/carabiner-dev/attestation"
)

// SubjectlessMatcher matches any attestation that does not have a subject.
// These typically are all that came from parsing plain json data, such as
// plain SBOMs published with artifacts.
type SubjectlessMatcher struct {
	HashSets []map[string]string
}

func (sm *SubjectlessMatcher) Matches(att attestation.Envelope) bool {
	if att.GetStatement() == nil {
		return false // Or true? Mmh...
	}

	if att.GetStatement().GetSubjects() == nil || len(att.GetStatement().GetSubjects()) == 0 {
		return true
	}

	return false
}
