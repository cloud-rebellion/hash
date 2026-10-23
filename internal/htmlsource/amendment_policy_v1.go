// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlsource

import "github.com/bright-interaction/hash/internal/htmlmaster"

func (v *RevisionValidationV1) HasAmendmentPolicyV1() bool {
	return v.validV1() && v.design != nil && v.design.rawMaster.ContractProfile != nil && v.design.rawMaster.ContractProfile.AmendmentPolicy != nil
}

// PresentedAmendmentPolicyV1 reuses this immutable validation's actual compiled
// current source. It never decodes a second caller-supplied document or master.
func (v *RevisionValidationV1) PresentedAmendmentPolicyV1() (*htmlmaster.PresentedAmendmentPolicyV1, error) {
	if !v.validV1() {
		return nil, invalid("revision validation scope")
	}
	if v.effective.Commitment == "" {
		return nil, nil
	}
	if err := v.ValidateV1(true); err != nil {
		return nil, err
	}
	if v.design == nil || v.design.rawCompiled == nil {
		return nil, invalid("missing current compiled source")
	}
	return v.design.rawCompiled.PresentedAmendmentPolicyV1(htmlmaster.Input{Values: v.effective.Values, Sections: v.effective.Sections})
}

// PresentedApprovedDataAmendmentPolicyV1 projects the actual validated current
// compiled clause without claiming a human review. Dispatch authority remains
// with the exact committed approved-data execution and native SQL producer.
func (v *RevisionValidationV1) PresentedApprovedDataAmendmentPolicyV1() (*htmlmaster.PresentedAmendmentPolicyV1, error) {
	if !v.validV1() {
		return nil, invalid("revision validation scope")
	}
	if v.effective.Commitment == "" {
		return nil, nil
	}
	if err := v.ValidateV1(false); err != nil {
		return nil, err
	}
	if v.design == nil || v.design.rawCompiled == nil {
		return nil, invalid("missing current compiled source")
	}
	return v.design.rawCompiled.PresentedAmendmentPolicyV1(htmlmaster.Input{Values: v.effective.Values, Sections: v.effective.Sections})
}
