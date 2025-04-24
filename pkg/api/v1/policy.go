// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"fmt"
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
