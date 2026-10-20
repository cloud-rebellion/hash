// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// This concrete adapter supplies only the SAME Work's actual admitted private
// recipient/field models. Branding is read at the original ordered policy point
// under its real scalar header/body loan and actual native SQL callback.
type applicationHTMLSendSigningStateV1 struct {
	work   *ApplicationHTMLSendWorkV1
	source *applicationHTMLRevisionSourceOwnerV1
}

func (w *ApplicationHTMLSendWorkV1) ValidateSigningPageStateV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	publicState := w.sourceState
	w.mu.Unlock()
	if publicState == nil {
		return ErrHTMLSendWorkV1
	}
	if !publicState.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer publicState.unlockV1()
	if publicState.closeRequested.Load() {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if w.sourceState != publicState || !w.valid(call) || w.sourceOwner == nil || !w.reviewedOriginalValidated || w.signingStateAttempted {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	owner := w.sourceOwner
	if err := owner.beginV1(); err != nil {
		w.mu.Unlock()
		return err
	}
	w.signingStateAttempted = true
	w.mu.Unlock()
	defer owner.finishV1()
	owner.mu.Lock()
	if owner.purpose != htmlSendSourcePurposeV1 || owner.processing || owner.validation == nil || owner.failure != nil {
		owner.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	owner.processing = true
	validation := owner.validation
	owner.mu.Unlock()
	defer func() { owner.mu.Lock(); owner.processing = false; owner.mu.Unlock() }()
	scratch, err := owner.stateComponentsV1()
	if err != nil {
		return err
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, scratch, 0); err != nil {
		return err
	}
	owner.stateScratchBase = scratch
	return validation.ValidateSigningPageStateV1(call, &applicationHTMLSendSigningStateV1{work: w, source: owner}, 0)
}
func (s *applicationHTMLSendSigningStateV1) ListRecipientsByDocument(call context.Context, id uuid.UUID) ([]*generated.Recipient, error) {
	if s == nil || s.work == nil || s.source == nil {
		return nil, ErrHTMLSendWorkV1
	}
	w := s.work
	if _, err := w.ReadRecipientsV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceOwner != s.source || id != w.session.state.document {
		return nil, ErrHTMLSendWorkV1
	}
	return w.sourceRecipients, nil
}
func (s *applicationHTMLSendSigningStateV1) ListFieldsByDocument(call context.Context, id uuid.UUID) ([]*generated.DocumentField, error) {
	if s == nil || s.work == nil || s.source == nil {
		return nil, ErrHTMLSendWorkV1
	}
	w := s.work
	if _, err := w.ReadFieldsV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceOwner != s.source || id != w.session.state.document {
		return nil, ErrHTMLSendWorkV1
	}
	if err := s.source.fieldOptionsComponentsV1(w.sourceFields); err != nil {
		return nil, err
	}
	return w.sourceFields, nil
}
func (s *applicationHTMLSendSigningStateV1) GetDocumentBrandingOverride(call context.Context, id uuid.UUID) (*generated.DocumentBrandingOverride, error) {
	if s == nil || s.work == nil || s.source == nil {
		return nil, ErrHTMLSendWorkV1
	}
	w := s.work
	if err := w.AcquireBrandingReadV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceOwner != s.source || id != w.session.state.document {
		return nil, ErrHTMLSendWorkV1
	}
	return w.queries.GetDocumentBrandingOverride(call, id)
}
