// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import "regexp"

// MatchesIdentity returns true if one of the verified signatures matches
// the identity.
func (v *Verification) MatchesIdentity(id *Identity) bool {
	if v.GetSignature() == nil {
		return false
	}

	return v.GetSignature().MatchesIdentity(id)
}

// HasIdentity returns true if one of the verifiers matches the passed identity
func (sv *SignatureVerification) MatchesIdentity(id *Identity) bool {
	switch {
	case id.GetSigstore() != nil:
		return sv.MatchesSigstoreIdentity(id.GetSigstore())
	case id.GetKey() != nil:
		return sv.MatchesKeyIdentity(id.GetKey())
	default:
		return false //  This would be an error
	}
}

// HasIdentity returns true if one of the verifiers matches the passed sigstore
// identity.
func (sv *SignatureVerification) MatchesSigstoreIdentity(id *IdentitySigstore) bool {
	// If the identity is missing either the issuer or its ID string, then
	// we reject it.
	if id.GetIdentity() == "" || id.GetIssuer() == "" {
		return false
	}

	// If this is a regexp matcher, compile them
	var regIdentity, regIssuer *regexp.Regexp
	if id.Mode != nil && *id.Mode == SigstoreModeRegexp {
		var err error
		regIdentity, err = regexp.Compile(id.GetIdentity())
		if err != nil {
			return false
		}
		regIssuer, err = regexp.Compile(id.GetIssuer())
		if err != nil {
			return false
		}
	}

	// Check each identity in the verification until one matches.
	for _, signer := range sv.Identities {
		if signer.GetSigstore() == nil {
			continue
		}

		if id.Mode == nil || *id.Mode == SigstoreModeExact {
			if signer.GetSigstore().GetIdentity() == id.GetIdentity() &&
				signer.GetSigstore().GetIssuer() == id.GetIssuer() {
				return true
			}
		} else if *id.Mode == SigstoreModeRegexp {
			if regIdentity.MatchString(signer.GetSigstore().GetIdentity()) &&
				regIssuer.MatchString(signer.GetSigstore().GetIssuer()) {
				return true
			}
		}
	}
	return false
}

// MatchesKeyIdentity returns true if one of the verified signatures was performed
// with the specified key.
func (sv *SignatureVerification) MatchesKeyIdentity(id *IdentityKey) bool {
	if id.GetId() == "" || id.GetData() == "" || id.GetType() == "" {
		return false
	}

	// Check each identity in the verification until one matches.
	for _, signer := range sv.Identities {
		keydata := signer.GetKey()
		if keydata == nil {
			continue
		}

		if id.GetId() == keydata.GetId() && id.GetData() == keydata.GetData() && id.GetType() == keydata.GetType() {
			return true
		}
	}
	return false
}
