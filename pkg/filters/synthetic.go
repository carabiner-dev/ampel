// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filters

import "github.com/carabiner-dev/ampel/pkg/attestation"

// The synthetic filters are mostly menat for testing but are freely usable
// and exportable in case there is a valid use case for them.

// AlwaysMatch is a filter that matches any attestation
type AlwaysMatch struct{}

func (AlwaysMatch) Matches(attestation.Envelope) bool { return true }

// NeverMatch is a filter implementation that never matches an attestation
type NeverMatch struct{}

func (NeverMatch) Matches(attestation.Envelope) bool { return false }
