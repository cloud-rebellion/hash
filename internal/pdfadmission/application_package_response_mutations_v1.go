// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type applicationPackageResponseMutationV1 struct {
	request                                                                   *applicationPackageResponseRequestV1
	capture                                                                   HTMLSendPackageCaptureMetadataV1
	attempt                                                                   uuid.UUID
	present, validated, auditStarted, recorded, retryRead, retryMatched, done bool
	checks                                                                    int
}

// This conjunction retains the original reader and the work's own native body
// through the actual transaction callback, including cancellation and copies.
func (w *ApplicationHTMLSendWorkV1) BeginPackageResponseV1(call context.Context, h *ApplicationPackageResponseRequestV1) (func(), error) {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return nil, ErrPackageResponseRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.packageResponse != nil || w.stage == nil || w.stage.operation == nil || w.familyRoot != nil || w.sourceDocument == nil || s.self != s || s.bound || s.consumerClosed || s.closed || s.reader == nil || s.grant == nil || s.ctx.Err() != nil || w.stage.operation.factory != s.factory || w.sourceDocument.OrgID != s.scope.org || w.sourceDocument.ID != s.scope.document || (s.kind == "signed" && w.stage.purpose != HTMLBlockSignMutationV1) || (s.kind == "accepted" && w.stage.purpose != HTMLAcknowledgementMutationV1) {
		return nil, ErrPackageResponseRequestV1
	}
	w.packageResponse = &applicationPackageResponseMutationV1{request: s}
	s.bound = true
	s.active++
	w.sourceBorrowers++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			w.mu.Lock()
			w.packageResponse.done = true
			w.sourceBorrowers--
			s.active--
			closes, actor := w.retireSourcesLockedV1()
			reader, grant := s.retireLockedV1()
			w.mu.Unlock()
			s.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			retireAcknowledgementRequestV1(reader, grant)
		})
	}, nil
}

func (w *ApplicationHTMLSendWorkV1) packageResponseRequestV1() *applicationPackageResponseRequestV1 {
	if w == nil || w.self != w {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.packageResponse == nil || w.packageResponse.done {
		return nil
	}
	return w.packageResponse.request
}

func (w *ApplicationHTMLSendWorkV1) ValidatePackageResponseV1(call context.Context) (failure error) {
	defer func() { failure = packageResponseFailureV1(failure) }()
	s := w.packageResponseRequestV1()
	if s == nil {
		return ErrPackageResponseRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.validatePackageResponseLockedV1(call, s)
}

func (w *ApplicationHTMLSendWorkV1) validatePackageResponseLockedV1(call context.Context, s *applicationPackageResponseRequestV1) error {
	m := w.packageResponse
	if !w.valid(call) || s.self != s || s.consumerClosed || s.closed || s.ctx.Err() != nil || m == nil || m.done || m.request != s || m.checks >= 2 || w.state == nil || w.sourceDocument == nil {
		return ErrPackageResponseRequestV1
	}
	m.checks++
	now := time.Now()
	if !now.Before(s.tokenExpiry.Time) || (s.documentExpiry.Valid && !now.Before(s.documentExpiry.Time)) {
		return ErrSignerReadCredentialV1
	}
	resolved, err := w.resolveSignerPackageCaptureLockedV1(call, s.scope)
	if err != nil {
		return err
	}
	defer resolved.close()
	if !resolved.observation.PackagePresent {
		if s.present || (m.validated && m.present) {
			return ErrPackageResponseChangedV1
		}
		m.validated = true
		return nil
	}
	if !s.present {
		return ErrPackageResponseRequiredV1
	}
	if resolved.capture == nil || !s.rootSHAValid || !applicationStampEqualV1(w.state.SentAt, s.sent) || !applicationStampEqualV1(w.state.Article13NoticeEpochAt, s.notice) || !w.state.Article13NoticeEpochV61Committed || !w.state.HasSupportedArticle13NoticeSchema || !bytes.Equal(w.sourceDocument.PdfSha256, s.rootSHA[:]) || resolved.capture.Manifest().Input().Main.PDF.SHA256 != hex.EncodeToString(s.rootSHA[:]) {
		return ErrSignerReadCredentialV1
	}
	c := resolved.observation.Capture
	if s.expected.ValidateV1() != nil || hex.EncodeToString(c.CanonicalSHA256[:]) != s.expected.ManifestSHA256 || hex.EncodeToString(c.CommitmentSHA256[:]) != s.expected.LegalCommitmentSHA256 {
		return ErrPackageResponseChangedV1
	}
	// The new database binding also locks the actual recipient before effects,
	// independently verifies current root/source and immutable M106/M103 identity,
	// and binds the exact database-authored incorporation version and copy.
	raw := int64(32768) + 8*int64(unsafe.Sizeof(generated.ListSignerPackageResponseBindingV1Row{})) + 16*int64(len(documentpackage.IncorporationTextV1))
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return errors.Join(ErrPackageResponseRequestV1, err)
	}
	defer closeRows()
	rows, err := w.queries.ListSignerPackageResponseBindingV1(call, generated.ListSignerPackageResponseBindingV1Params{DocumentID: s.scope.document, OrgID: s.scope.org, RecipientID: s.scope.recipient, TokenHash: s.scope.hash[:]})
	if err != nil {
		return err
	}
	copy := documentpackage.IncorporationCopyV1()
	if len(rows) != 1 || rows[0] == nil {
		return ErrPackageResponseChangedV1
	}
	r := rows[0]
	if r.AttemptID != resolved.attempt.AttemptID || r.PackageID != c.PackageID || r.CaptureRevision != c.Revision || !bytes.Equal(r.ManifestSha256, c.CanonicalSHA256[:]) || !bytes.Equal(r.LegalCommitmentSha256, c.CommitmentSHA256[:]) || !applicationStampEqualV1(r.SentAt, s.sent) || !applicationStampEqualV1(r.Article13NoticeEpochAt, s.notice) || !applicationStampV1(r.RetainUntil) || !r.RetainUntil.Time.Equal(resolved.attempt.RetainUntil) || r.MemberCount != c.MemberCount || r.IncorporationVersion != copy.Version || r.IncorporationText != copy.Text || hex.EncodeToString(r.IncorporationSha256) != copy.SHA256 {
		return ErrPackageResponseChangedV1
	}
	if m.validated && (!m.present || m.attempt != resolved.attempt.AttemptID || !reflect.DeepEqual(m.capture, c)) {
		return ErrPackageResponseChangedV1
	}
	m.present, m.validated, m.capture, m.attempt = true, true, c, resolved.attempt.AttemptID
	return nil
}

// This method binds the actual resolved capture, not caller identities. It
// returns the original purpose for a genuinely ordinary no-package response.
func (w *ApplicationHTMLSendWorkV1) PackageResponseAuditV1(call context.Context, payload map[string]any) (bool, error) {
	s := w.packageResponseRequestV1()
	if s == nil {
		return false, ErrPackageResponseRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.packageResponse
	if !w.valid(call) || s.closed || s.consumerClosed || s.ctx.Err() != nil || m == nil || m.done || !m.validated || m.auditStarted || payload == nil {
		return false, ErrPackageResponseRequestV1
	}
	if !m.present {
		return false, nil
	}
	if err := s.expected.BindAuditPayloadV1(payload, m.attempt.String(), m.capture.PackageID.String(), strconv.FormatInt(m.capture.Revision, 10), s.kind); err != nil {
		return false, err
	}
	return true, nil
}

func (w *ApplicationHTMLSendWorkV1) packageResponseAuditScopeMatchesV1(call context.Context, session *ApplicationSessionV1, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, payload map[string]any) bool {
	s := w.packageResponseRequestV1()
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.packageResponse
	if !w.valid(call) || w.session != session || s.closed || s.consumerClosed || s.ctx.Err() != nil || m == nil || m.done || !m.validated || !m.present || m.auditStarted || org != s.scope.org || document != s.scope.document || !recipient.Valid || uuid.UUID(recipient.Bytes) != s.scope.recipient || actor.Valid || (s.kind == "signed" && purpose != HTMLAuditPackageSignedV1) || (s.kind == "accepted" && purpose != HTMLAuditPackageAcknowledgedV1) {
		return false
	}
	expected := map[string]any{}
	if s.expected.BindAuditPayloadV1(expected, m.attempt.String(), m.capture.PackageID.String(), strconv.FormatInt(m.capture.Revision, 10), s.kind) != nil {
		return false
	}
	for k, v := range expected {
		if !reflect.DeepEqual(payload[k], v) {
			return false
		}
	}
	m.auditStarted = true
	return true
}

func (w *ApplicationHTMLSendWorkV1) NewPackageResponseAuditV1(call context.Context, kind, ip, ua string, payload map[string]any) (*ApplicationHTMLAuditEventConsumerV1, error) {
	s := w.packageResponseRequestV1()
	if s == nil {
		return nil, ErrPackageResponseRequestV1
	}
	s.mu.Lock()
	purpose := HTMLAuditPackageSignedV1
	if s.kind == "accepted" {
		purpose = HTMLAuditPackageAcknowledgedV1
	}
	org, document, recipient := s.scope.org, s.scope.document, s.scope.recipient
	s.mu.Unlock()
	if purpose.KindV1() != kind {
		return nil, ErrPackageResponseRequestV1
	}
	return w.session.newHTMLAuditEventCoreV1(call, purpose, org, document, pgtype.UUID{Bytes: recipient, Valid: true}, pgtype.UUID{}, kind, ip, ua, payload, nil, nil, nil, nil, w)
}

// The only accepted event authority is the actual just-appended audit owner in
// THIS native response transaction. SQL reads its real immutable row hash/time.
func (w *ApplicationHTMLSendWorkV1) RecordPackageResponseV1(call context.Context, owner *ApplicationHTMLAuditEventConsumerV1) (failure error) {
	defer func() { failure = packageResponseFailureV1(failure) }()
	s := w.packageResponseRequestV1()
	if s == nil {
		return ErrPackageResponseRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.packageResponse
	if !w.valid(call) || s.closed || s.consumerClosed || s.ctx.Err() != nil || m == nil || m.done || !m.validated || m.recorded {
		return ErrPackageResponseRequestV1
	}
	if err := w.validatePackageResponseLockedV1(call, s); err != nil {
		return err
	}
	if !m.present {
		m.recorded = true
		return nil
	}
	if owner == nil || owner.self != owner {
		return ErrPackageResponseRequestV1
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	purpose := HTMLAuditPackageSignedV1
	var signature pgtype.UUID
	if s.kind == "accepted" {
		purpose = HTMLAuditPackageAcknowledgedV1
	} else {
		if w.blockSignature == nil || w.blockSignature.signature == nil {
			return ErrPackageResponseRequestV1
		}
		signature = pgtype.UUID{Bytes: w.blockSignature.signature.ID, Valid: true}
	}
	if !m.auditStarted || owner.closed || owner.session != w.session || owner.purpose != purpose || owner.org != s.scope.org || owner.document != s.scope.document || !owner.recipient.Valid || uuid.UUID(owner.recipient.Bytes) != s.scope.recipient || owner.actor.Valid || !owner.used || !owner.attempted || owner.eventID == uuid.Nil {
		return ErrPackageResponseRequestV1
	}
	raw := int64(32768) + 8*int64(unsafe.Sizeof(generated.DocumentPackageResponsesV1{}))
	closeRow, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return errors.Join(ErrPackageResponseRequestV1, err)
	}
	defer closeRow()
	row, err := w.queries.RecordDocumentPackageResponseV1(call, generated.RecordDocumentPackageResponseV1Params{DocumentID: s.scope.document, OrgID: s.scope.org, RecipientID: s.scope.recipient, AttemptID: m.attempt, ExpectedManifestSha256: m.capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.capture.CommitmentSHA256[:], ResponseEventID: owner.eventID, SignatureID: signature})
	if err != nil {
		return err
	}
	if !packageResponseReceiptMatchesV1(row, s, m) || row.ResponseEventID != owner.eventID || row.SignatureID != signature {
		return ErrPackageResponseRequestV1
	}
	m.recorded = true
	return nil
}

func packageResponseReceiptMatchesV1(row *generated.DocumentPackageResponsesV1, s *applicationPackageResponseRequestV1, m *applicationPackageResponseMutationV1) bool {
	if row == nil || s == nil || m == nil {
		return false
	}
	return row.AttemptID == m.attempt && row.OrgID == s.scope.org && row.DocumentID == s.scope.document && row.RecipientID == s.scope.recipient && row.PackageID == m.capture.PackageID && row.CaptureRevision == m.capture.Revision && bytes.Equal(row.ManifestSha256, m.capture.CanonicalSHA256[:]) && bytes.Equal(row.LegalCommitmentSha256, m.capture.CommitmentSHA256[:]) && applicationStampEqualV1(row.SentAt, s.sent) && applicationStampEqualV1(row.Article13NoticeEpochAt, s.notice) && row.IncorporationVersion == s.expected.IncorporationVersion && hex.EncodeToString(row.IncorporationSha256) == s.expected.IncorporationSHA256 && row.ResponseKind == s.kind && row.ResponseEventID != uuid.Nil && len(row.ResponseEventRowSha256) == 32 && applicationStampV1(row.ResponseEventCreatedAt) && ((s.kind == "signed" && row.SignatureID.Valid) || (s.kind == "accepted" && !row.SignatureID.Valid))
}

// Identical retries observe the immutable receipt; they never append an event,
// retain an image or alter status a second time. Unknown commits are therefore
// safely recoverable when the original credential remains current.
func (w *ApplicationHTMLSendWorkV1) MatchPriorPackageResponseV1(call context.Context) (matched bool, failure error) {
	return w.matchPriorPackageResponseV1(call, nil)
}

// A signed retry must compare the actual incoming owned name/font with the
// immutable signature associated with the receipt. A matching package alone
// cannot turn a conflicting signature request into a successful retry.
func (w *ApplicationHTMLSendWorkV1) MatchPriorSignedPackageResponseV1(call context.Context, request *ApplicationBlockSignatureRequestV1) (matched bool, failure error) {
	if request == nil || request.state == nil {
		return false, ErrPackageResponseRequestV1
	}
	return w.matchPriorPackageResponseV1(call, request.state)
}

func (w *ApplicationHTMLSendWorkV1) matchPriorPackageResponseV1(call context.Context, signatureRequest *applicationBlockSignatureRequestV1) (matched bool, failure error) {
	defer func() { failure = packageResponseFailureV1(failure) }()
	s := w.packageResponseRequestV1()
	if s == nil {
		return false, ErrPackageResponseRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if signatureRequest != nil {
		signatureRequest.mu.Lock()
		defer signatureRequest.mu.Unlock()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.packageResponse
	if !w.valid(call) || s.closed || s.consumerClosed || s.ctx.Err() != nil || m == nil || m.done || !m.validated || m.retryRead {
		return false, ErrPackageResponseRequestV1
	}
	if s.kind == "signed" {
		if signatureRequest == nil || signatureRequest.self != signatureRequest || signatureRequest.closed || !signatureRequest.prepared || signatureRequest.grant == nil || signatureRequest.ctx == nil || signatureRequest.ctx.Err() != nil || signatureRequest.reader != s.reader || signatureRequest.snapshot == nil || signatureRequest.snapshot.org != s.scope.org || signatureRequest.snapshot.document != s.scope.document || signatureRequest.snapshot.recipient != s.scope.recipient || w.blockSignature == nil || w.blockSignature.request != signatureRequest {
			return false, ErrPackageResponseRequestV1
		}
	} else if signatureRequest != nil {
		return false, ErrPackageResponseRequestV1
	}
	m.retryRead = true
	if !m.present {
		return false, nil
	}
	raw := int64(32768) + 16*int64(unsafe.Sizeof(generated.DocumentPackageResponsesV1{}))
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return false, errors.Join(ErrPackageResponseRequestV1, err)
	}
	defer closeRows()
	rows, err := w.queries.GetDocumentPackageResponseV1(call, generated.GetDocumentPackageResponseV1Params{DocumentID: s.scope.document, OrgID: s.scope.org, RecipientID: s.scope.recipient})
	if err != nil {
		return false, err
	}
	if len(rows) != 1 || !packageResponseReceiptMatchesV1(rows[0], s, m) {
		return false, ErrPackageResponseChangedV1
	}
	if s.kind == "signed" {
		row := rows[0]
		identical, err := w.queries.MatchDocumentPackageSignedRetryV1(call, generated.MatchDocumentPackageSignedRetryV1Params{
			AttemptID: m.attempt, OrgID: s.scope.org, DocumentID: s.scope.document, RecipientID: s.scope.recipient,
			SignatureID: uuid.UUID(row.SignatureID.Bytes), ExpectedFont: signatureRequest.font, ExpectedTypedName: signatureRequest.typedName,
			ResponseEventID: row.ResponseEventID, ResponseEventRowSha256: row.ResponseEventRowSha256})
		if err != nil {
			return false, err
		}
		if !identical {
			return false, ErrPackageResponseChangedV1
		}
	}
	if !time.Now().Before(s.tokenExpiry.Time) || (s.documentExpiry.Valid && !time.Now().Before(s.documentExpiry.Time)) {
		return false, ErrSignerReadCredentialV1
	}
	m.retryMatched = true
	return true, nil
}

// Remaining responses are counted only after an exact observed retry receipt.
// The signed branch uses the genuine field-derived roles already retained by
// this same response work; callers cannot supply a convenient role collection.
func (w *ApplicationHTMLSendWorkV1) CountPackageResponseRetryRemainingV1(call context.Context) (remaining int64, failure error) {
	defer func() { failure = packageResponseFailureV1(failure) }()
	s := w.packageResponseRequestV1()
	if s == nil {
		return 0, ErrPackageResponseRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.packageResponse
	if !w.valid(call) || s.closed || s.consumerClosed || s.ctx.Err() != nil || m == nil || m.done || !m.retryMatched {
		return 0, ErrPackageResponseRequestV1
	}
	if s.kind == "accepted" {
		return w.queries.CountPendingAcceptors(call, s.scope.document)
	}
	if w.blockSignature == nil || w.blockSignature.roles == nil {
		return 0, ErrPackageResponseRequestV1
	}
	return w.queries.CountUnsignedSignersByRoles(call, generated.CountUnsignedSignersByRolesParams{DocumentID: s.scope.document, Roles: w.blockSignature.roles})
}

func packageResponseFailureV1(err error) error {
	if err == nil || errors.Is(err, ErrPackageResponseRequiredV1) || errors.Is(err, ErrPackageResponseChangedV1) || errors.Is(err, ErrSignerReadCredentialV1) || errors.Is(err, documentpackage.ErrResponseV1) {
		return err
	}
	return errors.Join(ErrPackageResponseRequestV1, err)
}
