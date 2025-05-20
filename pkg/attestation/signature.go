// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

// Signature abstracts a signature. At least for now.
type (
	Signature   interface{} //nolint:iface // To be implemented
	Certificate interface{} //nolint:iface // To be implemented
)

// Verification options abstracts the different options that can be tweaked
// to verify the various signature types
type VerificationOptions interface{} //nolint:iface // To be implemented
