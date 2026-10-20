// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/pdflayout"
)

// This fixed historical PDF role stage preserves the original signing-page
// decision, then actual recipients and fields, then RequiredRoles. Validation
// reuses this actual immutable native source, rather than recompiling a mutable
// caller document or treating a fitted/static policy as historical authority.
func (w *ApplicationHTMLSendWorkV1) historicalPDFSignatureRolesV1(call context.Context) ([]string, error) {
	source, err := w.NewSourceV1(call)
	if err != nil {
		return nil, err
	}
	state := source.state
	if !state.lockV1() {
		return nil, ErrBlockSignatureRequestV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() || state.owner == nil {
		return nil, ErrBlockSignatureRequestV1
	}
	owner := state.owner
	if err = owner.beginV1(); err != nil {
		return nil, err
	}
	defer owner.finishV1()
	validation, err := state.prepareValidationV1()
	if err != nil {
		return nil, err
	}
	scratch, err := owner.stateComponentsV1()
	if err != nil {
		return nil, err
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, scratch, 0); err != nil {
		return nil, err
	}
	owner.stateScratchBase = scratch
	if err = validation.ValidateSigningPageStateV1(call, &applicationHTMLSendSigningStateV1{work: w, source: owner}, 0); err != nil {
		return nil, err
	}
	if _, err = w.ReadRecipientsV1(call); err != nil {
		return nil, err
	}
	if _, err = w.ReadFieldsV1(call); err != nil {
		return nil, err
	}
	if err = state.holdPolicyV1(); err != nil {
		return nil, err
	}
	if err = owner.fieldOptionsComponentsV1(w.sourceFields); err != nil {
		return nil, err
	}
	roles, err := pdflayout.RequiredRolesPreparedHTMLV1(owner.snapshot.document, w.sourceRecipients, w.sourceFields, 0, validation)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.blockSignature == nil {
		return nil, ErrBlockSignatureRequestV1
	}
	w.blockSignature.roles = append([]string(nil), roles...)
	return roles, nil
}
