// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"context"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// Presentation reuses the actual send-frozen controller. It does not amend a
// legal snapshot, validate a company, select SMTP or replace ceremony policy.
// No mutable org name, operator name, request text or fallback is accepted.
func applicationTenantPresentationNameV1(document *generated.Document, confirmation *generated.DocumentLawfulBasisConfirmation) (string, error) {
	if document == nil || confirmation == nil || document.ID == uuid.Nil || document.OrgID == uuid.Nil ||
		confirmation.DocumentID != document.ID || confirmation.OrgID != document.OrgID || !confirmation.ConfirmedAt.Valid ||
		strings.TrimSpace(document.LawfulBasis) == "" || strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(document.LawfulBasis) ||
		strings.TrimSpace(confirmation.ControllerContact) == "" || strings.TrimSpace(confirmation.ControllerName) == "" {
		return "", ErrHTMLSendWorkV1
	}
	return strings.TrimSpace(confirmation.ControllerName), nil
}

// Caller holds the same Work mutex. The original scoped header/body query
// acquires actual retained credit and retains the confirmation until all real
// consumers join. Each producer separately prices/clones its new presentation.
func (w *ApplicationHTMLSendWorkV1) readTenantPresentationNameLockedV1(call context.Context, document *generated.Document) (string, error) {
	if w == nil || w.self != w || w.session == nil || w.session.state == nil || !w.valid(call) || document == nil || document.ID != w.logicalDocumentV1() || document.OrgID != w.session.state.org {
		return "", ErrHTMLSendWorkV1
	}
	confirmation, err := w.readConfirmationLockedV1(call)
	if err != nil {
		return "", err
	}
	return applicationTenantPresentationNameV1(document, confirmation)
}

// Participant changes use the same M93 document/org header and measured
// confirmation body through their existing retained revision owner. The
// private snapshot and operation choose scope, never a request/company string.
func (w *ApplicationHTMLCeremonyWorkflowV1) readTenantPresentationNameV1(call context.Context) (string, error) {
	if !w.validCallV1(call) {
		return "", ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.snapshot == nil || w.snapshot.document == nil || w.closed {
		w.mu.Unlock()
		return "", ErrHTMLCeremonyWorkflowV1
	}
	document := w.snapshot.document
	op := w.operation.state
	w.mu.Unlock()
	if document.ID != op.document || document.OrgID != op.org {
		return "", ErrHTMLCeremonyWorkflowV1
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return "", err
	}
	header, err := q.GetSignerControllerReadHeaderV1(call, generated.GetSignerControllerReadHeaderV1Params{DocumentID: op.document, OrgID: op.org})
	if err != nil {
		return "", err
	}
	if header == nil || header.DocumentID != op.document || header.OrgID != op.org {
		return "", ErrHTMLCeremonyWorkflowV1
	}
	if err = w.retainV1(call, header.RawTextBytes, 0); err != nil {
		return "", err
	}
	confirmation, err := q.ReadSignerLawfulBasisConfirmationV1(call, generated.ReadSignerLawfulBasisConfirmationV1Params{DocumentID: op.document, OrgID: op.org, ExpectedRawTextBytes: header.ConfirmationRawTextBytes})
	if err != nil {
		return "", err
	}
	if confirmation == nil || int64(len(confirmation.LawfulBasis)+len(confirmation.Via)+len(confirmation.ControllerName)+len(confirmation.ControllerContact)) != header.ConfirmationRawTextBytes {
		return "", ErrHTMLCeremonyWorkflowV1
	}
	return applicationTenantPresentationNameV1(document, confirmation)
}
