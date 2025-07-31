// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filters

import (
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/ampel/pkg/attestation"
)

type SubjectHashMatcher struct {
	HashSets []map[string]string
}

func (sm *SubjectHashMatcher) Matches(att attestation.Envelope) bool {
	if att.GetStatement() == nil {
		return false
	}

	for _, sb := range att.GetStatement().GetSubjects() {
		if sb.GetDigest() == nil {
			continue
		}

		for _, hs := range sm.HashSets {
			match := false
			for subalgo, subdig := range sb.GetDigest() {
				// If the filter does not have the algorithm
				// in the attestation, continue to the next.
				if _, ok := hs[subalgo]; !ok {
					continue
				}

				if hs[subalgo] == subdig {
					logrus.Debugf("%s:%s = %s", subalgo, hs[subalgo], subdig)
					// We have a match, but we cannot return it now as
					// we need to check all algos.
					match = true
				} else {
					logrus.Debugf("%s != %s ", hs[subalgo], subdig)
					// If the hashset has the algo but does not match we can
					// bail now.
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}

	return false
}
