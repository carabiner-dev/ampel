// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filters

import (
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/sirupsen/logrus"
)

type SubjectHashMatcher struct {
	HashSets []map[string]string
}

func (sm *SubjectHashMatcher) Match(att attestation.Envelope) bool {
	if att.GetStatement() == nil {
		return false
	}

	for _, sb := range att.GetStatement().GetSubjects() {
		if sb.GetDigest() == nil {
			continue
		}
	HASHSETLOOP:
		for _, hs := range sm.HashSets {
			match := false
			for subalgo, subdig := range sb.GetDigest() {
				if _, ok := hs[subalgo]; !ok {
					continue
				}

				if hs[subalgo] == subdig {
					logrus.Infof("%s:%s = %s", subalgo, hs[subalgo], subdig)
					// We have one match
					match = true
				} else {
					logrus.Infof("%s != %s ", hs[subalgo], subdig)
					// If the hashset has the algo but
					continue HASHSETLOOP
				}
			}
			if match {
				return true
			}
		}
		return false
	}

	return false
}
