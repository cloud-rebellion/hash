// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// applicationRequestPayloadAdmissionV1 is private and uses the SAME real owned
// session/factory admission/coordinator. It supplies only resource accounting.
// Caller UUIDs, this adapter and a granted loan supply no original credential,
// source/party proof, READY, commit-disposition or permission to dispatch Sign.
// The future atomic driver keeps the session's one actual admission handle and
// reconciles it outside entity locks after consumer/physical SQL retirement.
type applicationRequestPayloadAdmissionV1 struct {
	session     *pdfadmission.ApplicationSessionV1
	scope       pdfadmission.ApplicationScopeV1
	recipientID uuid.UUID
}

func (e *Engine) newApplicationRequestPayloadAdmissionV1(ctx context.Context, rc *RecipientContext, intent *fittedSigningIntentV1, session *pdfadmission.ApplicationSessionV1, scope pdfadmission.ApplicationScopeV1) (*applicationRequestPayloadAdmissionV1, error) {
	p, err := e.requestPayloadPrivateAdmissionV1(ctx, rc, intent, false)
	if err != nil {
		return nil, err
	}
	if session == nil || scope.OrgID != p.orgID || scope.DocumentID != p.documentID || scope.AdmissionID == uuid.Nil || scope.OwnerID == uuid.Nil || !requestHexV1(scope.StaticBasisSHA256) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	return &applicationRequestPayloadAdmissionV1{session: session, scope: scope, recipientID: p.recipientID}, nil
}
func (a *applicationRequestPayloadAdmissionV1) AcquireRequestPayloadV1(ctx context.Context, b requestPayloadBudgetV1) (func(), error) {
	if err := requestPayloadCheckContextV1(ctx); err != nil {
		return nil, err
	}
	if a == nil || a.session == nil || a.recipientID == uuid.Nil || b.OrgID != a.scope.OrgID || b.DocumentID != a.scope.DocumentID || b.RecipientID != a.recipientID {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	cost := pdfadmission.ApplicationRequestPayloadCostV1{OriginBytes: b.OriginBytes, IntentBytes: b.IntentBytes, RawContextBytes: b.RawContextBytes}
	resources, err := pdfadmission.ApplicationRequestPayloadResourcesForV1(cost)
	if err != nil || resources.WorkingBytes != b.WorkingBytes {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	closeConsumer, err := a.session.AcquireRequestPayloadV1(ctx, a.scope, a.recipientID, cost)
	if err != nil {
		return nil, requestPayloadErrorV1(ctx, err)
	}
	if closeConsumer == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		closeConsumer()
		return nil, err
	}
	// The codec holds this private consumer loan through every clone/use. The
	// actual admission also retains its coordinator grant until the real fence
	// retires; calling this closure never manufactures physical/debt proof.
	return closeConsumer, nil
}

// Acquire the finite scalar-header loan before reading/locking the scoped M90
// header. The active AdmissionID is intentionally not needed before that query.
func (e *Engine) acquireApplicationRequestHeaderV1(ctx context.Context, rc *RecipientContext, session *pdfadmission.ApplicationSessionV1) (func(), error) {
	if err := requestPayloadCheckContextV1(ctx); err != nil {
		return nil, err
	}
	if e == nil || rc == nil || rc.presentedCredential == nil || rc.presentedCredential.issuer != e || rc.Recipient == nil || rc.Document == nil || session == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	p := rc.presentedCredential
	// Scalar provenance only: no whole raw equality, notice Validate/Marshal,
	// typed intent issuance or strings.TrimSpace before current/original work loans.
	if p.orgID == uuid.Nil || p.documentID == uuid.Nil || p.recipientID == uuid.Nil || rc.Document.OrgID != p.orgID || rc.Document.ID != p.documentID || rc.Recipient.ID != p.recipientID || rc.Recipient.DocumentID != p.documentID || rc.Recipient.DocOrgID != p.orgID ||
		p.signingPolicy != "pdf-static-v1" || p.sourceKind != "pdf" || p.routingTier != "SES" || !p.requiresSignature || p.isEnvelope || p.parentEnvelopeID.Valid || p.documentDeletedAt.Valid ||
		!finiteFittedTimeV1(p.recipientExpiry) || (p.documentExpiry.Valid && !finiteFittedTimeV1(p.documentExpiry)) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err := p.originalLiveV1(e.now()); err != nil {
		return nil, err
	}
	closeConsumer, err := session.AcquireRequestHeaderV1(ctx, p.orgID, p.documentID, p.recipientID)
	if err != nil {
		return nil, requestPayloadErrorV1(ctx, err)
	}
	if closeConsumer == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		closeConsumer()
		return nil, err
	}
	return closeConsumer, nil
}

// Production admission may reserve the genuine supported origin/intent and
// canonical87 authority/span maxima BEFORE private intent/authority/span work.
// Later capture uses exact codec counts; recovery uses the immutable scoped M90
// scalar metadata before BYTEA reads. If87 cheap lengths are not available,
// callers reserve BOTH supported1MiB maxima BEFORE its metadata/body read or
// generation; a PDF phase or uncharged basis borrow cannot substitute.
// CurrentContextBytes is the cheap header7lengths+8192 sum; OriginalRawContextBytes
// is the private receipt5raw lengths; PolicyBytes covers exact preserved policy
// HTML/variables/required rows from the admitted cheap projection header. Every
// addition and fixed multiplication is separately overflow validated.
func (a *applicationRequestPayloadAdmissionV1) acquireJournalV1(ctx context.Context, cost pdfadmission.ApplicationRequestJournalCostV1) (func(), error) {
	if err := requestPayloadCheckContextV1(ctx); err != nil {
		return nil, err
	}
	if a == nil || a.session == nil || a.recipientID == uuid.Nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if _, err := pdfadmission.ApplicationRequestJournalResourcesForV1(cost); err != nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	closeConsumer, err := a.session.AcquireRequestJournalV1(ctx, a.scope, a.recipientID, cost)
	if err != nil {
		return nil, requestPayloadErrorV1(ctx, err)
	}
	if closeConsumer == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		closeConsumer()
		return nil, err
	}
	return closeConsumer, nil
}
