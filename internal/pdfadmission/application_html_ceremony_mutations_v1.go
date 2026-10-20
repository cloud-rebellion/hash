// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (w *ApplicationHTMLCeremonyWorkflowV1) queriesV1(call context.Context) (*generated.Queries, error) {
	if !w.validCallV1(call) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	return generated.New(&applicationOwnedDBTXV1{session: w.stage.state.session.state}), nil
}

// The earlier actual actor/document/credential/CAS/source policy remains with
// its original fixed adapter. This method funds the actual full returned row
// before SQL, including the fresh32-byte review digest, on the SAME header.
func (w *ApplicationHTMLCeremonyWorkflowV1) MarkReviewedV1(call context.Context, expected time.Time, pdf []byte) (*generated.Document, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyReviewV1 || len(pdf) != 32 || w.operation.state.actor == uuid.Nil {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err := w.captureBodyV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	if w.reviewAttempted {
		w.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.reviewAttempted = true
	original := w.snapshot.document
	w.mu.Unlock()
	raw, err := htmlAuthoringSumV1(signerDocumentRawBytesV1(original), 32)
	if err != nil {
		return nil, err
	}
	wire, err := htmlCeremonyDocumentWireV1(original)
	if err != nil {
		return nil, err
	}
	if err = w.retainV1(call, raw, wire); err != nil {
		return nil, err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	document, err := q.MarkDocumentHTMLReviewed(call, generated.MarkDocumentHTMLReviewedParams{ID: original.ID, OrgID: original.OrgID,
		ExpectedUpdatedAt: pgtype.Timestamptz{Time: expected, Valid: true}, ExpectedPdfSha256: bytes.Clone(pdf), ReviewedBy: w.operation.state.actor})
	if err != nil {
		return nil, err
	}
	if document == nil || document.ID != original.ID || document.OrgID != original.OrgID || signerDocumentRawBytesV1(document) > raw {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlCeremonyDocumentWireV1(document)
	if err != nil || actual != wire {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	w.updated = htmlRevisionCloneDocumentV1(document)
	w.mu.Unlock()
	return document, nil
}
func htmlCeremonyDocumentWireV1(document *generated.Document) (int64, error) {
	if document == nil {
		return 0, ErrHTMLCeremonyWorkflowV1
	}
	return htmlAuthoringSumV1(int64(len(document.HtmlSourceJson)), int64(len(document.HtmlCurrentSourceJson)),
		int64(len(document.VariablesJson)), int64(len(document.BlocksJson)), int64(len(document.Metadata)), int64(len(document.MetadataRedactionReport)))
}

// Archive the complete ORIGINAL ceremony before any reopen/reset/token write.
// Both native source and collection borrowers span grant->dispatch->returned
// measurement. Only this exact fresh captured UUID can be measured here.
func (w *ApplicationHTMLCeremonyWorkflowV1) CaptureRetiredV1(call context.Context, source *ApplicationHTMLRevisionSourceV1, collections *ApplicationHTMLRevisionCollectionsV1) error {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyRetireV1 || source == nil || source.state == nil || collections == nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	if err := w.captureBodyV1(call); err != nil {
		return err
	}
	s := source.state
	if s.operation != w.operation.state || s.snapshot != w.snapshot || s.purpose != htmlCeremonySourcePurposeV1 || collections.reader != w.reader || collections.snapshot != w.snapshot {
		return ErrHTMLCeremonyWorkflowV1
	}
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	done, err := collections.beginV1(call, w.snapshot.document.ID)
	if err != nil {
		return err
	}
	defer done()
	w.mu.Lock()
	if w.capturedRetired {
		w.mu.Unlock()
		return ErrHTMLCeremonyWorkflowV1
	}
	original := w.snapshot.document
	w.mu.Unlock()
	// The original helper is Validate(true)->Current->Commitment->capture.
	if err = source.ValidateRetirementReviewV1(); err != nil {
		return err
	}
	// The caller validated Current before admitting the complete collections.
	// Keep that original error order and require this exact owner's completed
	// result; invoking the one-shot validator again always refuses a valid source.
	s.mu.Lock()
	currentValidated := s.currentValidated && s.validation != nil && s.failure == nil && !s.processing
	s.mu.Unlock()
	if !currentValidated {
		return ErrHTMLRevisionSourceV1
	}
	commitment, err := source.CommitmentV1()
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(commitment)
	if err != nil || len(digest) != 32 {
		return htmlmaterialization.ErrInvalid
	}
	if err = collections.acquireStatementV1(call, htmlRevisionSnapshotCaptureStageV1); err != nil {
		return err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return err
	}
	actor := pgtype.UUID{}
	if w.operation.state.actor != uuid.Nil {
		actor = pgtype.UUID{Bytes: w.operation.state.actor, Valid: true}
	}
	id, err := q.CaptureHTMLRevisionSnapshotIDV1(call, generated.CaptureHTMLRevisionSnapshotIDV1Params{DocumentID: original.ID, OrgID: original.OrgID,
		ExpectedUpdatedAt: original.UpdatedAt, Kind: "ceremony_retired", SourceCommitment: digest, CreatedBy: actor})
	if err != nil {
		return err
	}
	if id == uuid.Nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	if err = collections.acquireStatementV1(call, htmlRevisionSnapshotMeasureStageV1); err != nil {
		return err
	}
	measured, err := q.MeasureHTMLRevisionSnapshotWireV1(call, generated.MeasureHTMLRevisionSnapshotWireV1Params{DocumentID: original.ID, OrgID: original.OrgID, SnapshotID: id})
	if err != nil {
		return err
	}
	if measured == nil || measured.SnapshotID != id || measured.DocumentID != original.ID || measured.OrgID != original.OrgID || measured.MeasurementServerVersionNum != collections.header.ServerVersionNum {
		return ErrHTMLCeremonyWorkflowV1
	}
	wire, err := htmlRevisionSnapshotSumV1(measured.SourceWireBytes, measured.FieldsWireBytes, measured.RecipientsWireBytes, measured.NoticeWireBytes, measured.CeremonyEventsWireBytes, measured.ReportWireBytes)
	if err != nil || wire > collections.components.freshSnapshotJSONBytes || measured.RawTextBytes < 0 || measured.RawTextBytes > collections.components.freshSnapshotRawBytes {
		return ErrHTMLCeremonyWorkflowV1
	}
	if !w.validCallV1(call) {
		return ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	w.capturedRetired = true
	w.mu.Unlock()
	return nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ReopenDraftV1(call context.Context) (*generated.Document, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyRetireV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	// An actual non-HTML source has no HTML retirement snapshot, exactly
	// as the original CaptureRetiredCeremony no-op. Never fake that capture
	// or waive it for a source whose private original HTML body is present.
	if w.snapshot == nil || w.snapshot.document == nil || (len(w.snapshot.document.HtmlSourceJson) != 0 && !w.capturedRetired) || w.reopenAttempted {
		w.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.reopenAttempted = true
	original := w.snapshot.document
	w.mu.Unlock()
	raw := signerDocumentRawBytesV1(original)
	wire, err := htmlCeremonyDocumentWireV1(original)
	if err != nil {
		return nil, err
	}
	if err = w.retainV1(call, raw, wire); err != nil {
		return nil, err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	document, err := q.ReopenDocumentToDraft(call, generated.ReopenDocumentToDraftParams{ID: original.ID, OrgID: original.OrgID})
	if err != nil {
		return nil, applicationInternalWriteErrorV1(call, applicationCeremonyReopenWriteV1, err)
	}
	if document == nil || document.ID != original.ID || document.OrgID != original.OrgID || document.Status != "draft" || signerDocumentRawBytesV1(document) > raw {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlCeremonyDocumentWireV1(document)
	if err != nil || actual != wire {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	w.updated = htmlRevisionCloneDocumentV1(document)
	w.mu.Unlock()
	return document, nil
}

// This early body loan is used only for actual policy projections/recipient
// rows before six-JSON cache admission. The workflow's actual callback/result
// conjunction retains the original real reader/header through their last use.
func (w *ApplicationHTMLCeremonyWorkflowV1) retainHeaderBodyV1(call context.Context, raw int64) error {
	if !w.validCallV1(call) || raw < 0 {
		return ErrHTMLCeremonyWorkflowV1
	}
	close, err := w.reader.authoring.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return errors.Join(ErrHTMLCeremonyWorkflowV1, err)
	}
	w.mu.Lock()
	w.closeConsumers = append(w.closeConsumers, close)
	closed := w.closed
	w.mu.Unlock()
	if closed || call.Err() != nil {
		return ErrHTMLCeremonyWorkflowV1
	}
	return nil
}
func (w *ApplicationHTMLCeremonyWorkflowV1) ReadParticipantV1(call context.Context) (*generated.Recipient, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 || w.operation.state.participant == nil {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	scope := w.operation.state.participant
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	header, err := q.GetHTMLCeremonyParticipantRecipientHeaderV1(call, generated.GetHTMLCeremonyParticipantRecipientHeaderV1Params{DocumentID: scope.document, OrgID: scope.org, RecipientID: scope.recipient})
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != scope.document || header.OrgID != scope.org || header.RecipientID != scope.recipient || header.RawTextBytes < 0 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err = w.retainHeaderBodyV1(call, header.RawTextBytes); err != nil {
		return nil, err
	}
	// Original UUID-only row domain. The actual private credential, rather than
	// this read predicate, determines whether a rotated hash or changed role is
	// still valid. The parent/recipient locks keep the measured body unchanged.
	row, err := q.GetRecipientForShare(call, generated.GetRecipientForShareParams{ID: scope.recipient, DocumentID: scope.document, OrgID: scope.org})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != scope.recipient || row.DocumentID != scope.document {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlAuthoringSumV1(int64(len(row.Role)), int64(len(row.Email)), int64(len(row.Name)), int64(len(row.Status)), int64(len(row.DeclinedReason.String)), int64(len(row.Locale)), int64(len(row.MagicTokenHash)))
	if err != nil || actual != header.RawTextBytes {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	recipient := *row
	recipient.MagicTokenHash = bytes.Clone(row.MagicTokenHash)
	recipient.Role, recipient.Email, recipient.Name = strings.Clone(row.Role), strings.Clone(row.Email), strings.Clone(row.Name)
	recipient.Status, recipient.Locale = strings.Clone(row.Status), strings.Clone(row.Locale)
	recipient.DeclinedReason.String = strings.Clone(row.DeclinedReason.String)
	w.mu.Lock()
	w.participant = &recipient
	w.mu.Unlock()
	return row, nil
}

func (w *ApplicationHTMLCeremonyWorkflowV1) ReadNotificationSenderV1(call context.Context) (*generated.User, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err := w.captureBodyV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	document := w.snapshot.document
	already := w.sender != nil
	w.mu.Unlock()
	if already {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	header, err := q.GetHTMLChangeNotificationSenderHeaderV1(call, generated.GetHTMLChangeNotificationSenderHeaderV1Params{DocumentID: document.ID, OrgID: document.OrgID})
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != document.ID || header.OrgID != document.OrgID || header.UserID != document.SenderID || header.RawTextBytes < 0 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err = w.retainV1(call, header.RawTextBytes, 0); err != nil {
		return nil, err
	}
	sender, err := q.ReadHTMLChangeNotificationSenderV1(call, generated.ReadHTMLChangeNotificationSenderV1Params{DocumentID: document.ID, OrgID: document.OrgID,
		ExpectedUserID: header.UserID, ExpectedUserOrgID: header.UserOrgID, ExpectedRawTextBytes: header.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if sender == nil || sender.ID != header.UserID || sender.OrgID != header.UserOrgID {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlAuthoringSumV1(int64(len(sender.Name)), int64(len(sender.Email)), int64(len(sender.Role)), int64(len(sender.ZitadelSub.String)))
	if err != nil || actual != header.RawTextBytes {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	copy := *sender
	copy.Name, copy.Email, copy.Role = strings.Clone(sender.Name), strings.Clone(sender.Email), strings.Clone(sender.Role)
	copy.ZitadelSub.String = strings.Clone(sender.ZitadelSub.String)
	w.mu.Lock()
	w.sender = &copy
	w.mu.Unlock()
	return sender, nil
}

func (w *ApplicationHTMLCeremonyWorkflowV1) PauseForChangesV1(call context.Context) error {
	if !w.validCallV1(call) || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 {
		return ErrHTMLCeremonyWorkflowV1
	}
	if err := w.captureBodyV1(call); err != nil {
		return err
	}
	w.mu.Lock()
	original := w.snapshot.document
	ready := w.change != nil
	w.mu.Unlock()
	if !ready {
		return ErrHTMLCeremonyWorkflowV1
	}
	raw, err := htmlAuthoringSumV1(signerDocumentRawBytesV1(original), int64(len("changes_requested")))
	if err != nil {
		return err
	}
	wire, err := htmlCeremonyDocumentWireV1(original)
	if err != nil {
		return err
	}
	if err = w.retainV1(call, raw, wire); err != nil {
		return err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return err
	}
	document, err := q.RequestChangesOnDocument(call, generated.RequestChangesOnDocumentParams{ID: original.ID, OrgID: original.OrgID})
	if err != nil {
		return err
	}
	if document == nil || document.ID != original.ID || document.OrgID != original.OrgID || document.Status != "changes_requested" || signerDocumentRawBytesV1(document) > raw {
		return ErrHTMLCeremonyWorkflowV1
	}
	actual, err := htmlCeremonyDocumentWireV1(document)
	if err != nil || actual != wire {
		return ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	w.updated = htmlRevisionCloneDocumentV1(document)
	w.mu.Unlock()
	return nil
}
