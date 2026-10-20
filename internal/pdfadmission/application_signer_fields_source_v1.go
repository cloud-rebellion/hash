// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "context"

// This is the original fields Validate(doc,false)/Current policy. It uses the
// staged source producers and actual locked current projection; it cannot set
// the independent Send review flags or adopt a caller-supplied source/model.
func (w *ApplicationHTMLSendWorkV1) ValidateSignerFieldsMaterializationV1(call context.Context) error {
	s := w.signerFieldsRequestV1()
	if s == nil {
		return ErrSignerFieldsRequestV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.signerFields == nil || w.signerFields.materialized || w.stage.purpose != HTMLSignerFieldsMutationV1 {
		w.mu.Unlock()
		return ErrSignerFieldsRequestV1
	}
	w.mu.Unlock()
	source, err := w.NewSourceV1(call)
	if err != nil {
		return err
	}
	state := source.state
	if !state.lockV1() {
		return ErrSignerFieldsRequestV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() || state.candidate || state.work != w || state.owner == nil {
		return ErrSignerFieldsRequestV1
	}
	v, err := state.prepareValidationV1()
	if err != nil {
		return err
	}
	if err = v.ValidateV1(false); err != nil {
		return err
	}
	owner := state.owner
	current, err := w.readCurrentForSourceV1(owner)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	if owner.snapshot == nil {
		owner.mu.Unlock()
		return ErrSignerFieldsRequestV1
	}
	owner.snapshot.current = current
	plain := len(owner.snapshot.document.HtmlSourceJson) == 0
	owner.mu.Unlock()
	if !plain {
		if err = (&ApplicationHTMLRevisionSourceV1{state: owner}).ValidateCurrentV1(); err != nil {
			return err
		}
	} else if current != nil {
		return ErrSignerFieldsRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.signerFields == nil || w.signerFields.request != s || w.signerFields.done {
		return ErrSignerFieldsRequestV1
	}
	w.signerFields.materialized = true
	return nil
}
