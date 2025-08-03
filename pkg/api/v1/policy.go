// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	intoto "github.com/in-toto/attestation/go/v1"
)

func (meta *Meta) testsControl(ctrl *Control) bool {
	if meta.GetControls() == nil {
		return false
	}
	for _, c := range meta.GetControls() {
		if ctrl.Class == "" {
			if c.GetId() == ctrl.GetId() {
				return true
			}
		} else {
			if c.GetId() == ctrl.GetId() && c.GetClass() == ctrl.GetClass() {
				return true
			}
		}
	}
	return false
}

func (policy *Policy) TestsControl(ctrl *Control) bool {
	if ctrl == nil {
		return false
	}

	if policy.GetMeta() == nil {
		return false
	}
	return policy.GetMeta().testsControl(ctrl)
}

// NewIdentityFromSlug returns a new identity by parsing a slug string.
//
// There are three kinds of identities supported: sigstore, key and reference.
func NewIdentityFromSlug(slug string) (*Identity, error) {
	itype, identityString, ok := strings.Cut(slug, "::")
	if !ok {
		refId, isRef := strings.CutPrefix(slug, "ref:")
		if isRef {
			return &Identity{Ref: &IdentityRef{Id: refId}}, nil
		}
	}

	switch itype {
	case "sigstore", "sigstore(regexp)":
		issuer, ident, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse sigstore identity from identity string")
		}
		mode := "exact"
		if itype == "sigstore(regexp)" {
			mode = "regexp"
		}
		return &Identity{
			Sigstore: &IdentitySigstore{
				Mode:     &mode,
				Issuer:   issuer,
				Identity: ident,
			},
		}, nil
	case "key":
		keyType, keyId, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse key details from identity string")
		}
		return &Identity{
			Key: &IdentityKey{
				Id:   keyId,
				Type: keyType,
			},
		}, nil
	}
	return nil, fmt.Errorf("unable to parse identity from slug string")
}

// Slug returns a string representing the identity
func (i *Identity) Slug() string {
	switch {
	case i.GetSigstore() != nil:
		mode := ""
		if i.GetSigstore().GetMode() == "regexp" {
			mode = "(regexp)"
		}
		return fmt.Sprintf("sigstore%s::%s::%s", mode, i.GetSigstore().GetIssuer(), i.GetSigstore().GetIdentity())
	case i.GetKey() != nil:
		return fmt.Sprintf("key::%s::%s", i.GetKey().GetType(), i.GetKey().GetId())
	case i.GetRef() != nil:
		return fmt.Sprintf("ref:%s", i.GetRef().GetId())
	default:
		return ""
	}
}

// Validate checks the integrity of the identity and returns an error if
// fields are missing or invalid
func (i *Identity) Validate() error {
	if i.GetKey() == nil && i.GetSigstore() == nil {
		return fmt.Errorf("identity has no sigstore or key data")
	}

	errs := []error{}
	if i.GetSigstore() != nil {
		if i.GetSigstore().GetIssuer() == "" {
			errs = append(errs, fmt.Errorf("sigstore identity has no issuer defined"))
		}

		if i.GetSigstore().GetIdentity() == "" {
			errs = append(errs, fmt.Errorf("sigstore identity has no identifier (email/account) defined"))
		}
	}

	if i.GetKey() != nil {
		if i.GetKey().GetId() == "" {
			errs = append(errs, errors.New("key identity has no key ID defined"))
		}
		if i.GetKey().GetData() == "" {
			errs = append(errs, errors.New("key identity has no key data set"))
		}
	}
	return errors.Join(errs...)
}

// GetSourceURL returns the URL to fetch the policy. First, it will try the
// DownloadLocation, if empty returns the UR
func (ref *PolicyRef) GetSourceURL() string {
	if ref.GetLocation() == nil {
		return ""
	}

	if ref.GetLocation().GetDownloadLocation() != "" {
		return ref.GetLocation().GetDownloadLocation()
	}
	return ref.GetLocation().GetUri()
}

// Validate returns an error if the reference is not valid
func (ref *PolicyRef) Validate() error {
	errs := []error{}

	// If the download URL is not a VCS locator, the policy MUST have at least one hash
	if ref.GetLocation() != nil {
		uri := ref.GetLocation().GetUri()
		if uri == "" {
			uri = ref.GetLocation().GetDownloadLocation()
		}

		// Ensure a remote reference hash a hash or digest
		if len(ref.GetLocation().GetDigest()) == 0 {
			// VCS locators can have a commit or a hash
			if strings.HasPrefix(uri, "git+") {
				l := vcslocator.Locator(uri)
				parts, err := l.Parse()
				if err != nil {
					errs = append(errs, fmt.Errorf("parsing VCS locator: %w", err))
				} else if parts.Commit == "" {
					errs = append(errs, errors.New("remoter policies referenced by VCS locator require a digest or commit hash"))
				}
			} else if uri != "" {
				errs = append(errs, errors.New("remote policies referenced by URL require at least one hash"))
			}
		} else {
			for algo := range ref.GetLocation().GetDigest() {
				if _, ok := intoto.HashAlgorithms[algo]; !ok {
					errs = append(errs, fmt.Errorf("unknown algorithm %q in reference digest", algo))
				}
			}
		}
	}

	// TODO Check hash algorithms to be valid (from the intoto catalog)

	return errors.Join(errs...)
}

func (set *PolicySet) Validate() error {
	errs := []error{}
	for _, p := range set.GetPolicies() {
		if err := p.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *Policy) Validate() error {
	errs := []error{}

	for _, i := range p.GetIdentities() {
		if err := i.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
