// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AppendV1 retains ONE outer collection/source/candidate use across every
// scalar-derived statement grant, exact SQL dispatch, trigger work, returned
// row and original source/report check. acquireStatement alone is never treated
// as a durable dispatch lease. Nothing commits or retries a mutation here.
func (w *ApplicationHTMLRevisionWriterV1) AppendV1(call context.Context) error {
	done, err := w.beginV1(call)
	if err != nil {
		return err
	}
	defer done()
	s := w.source
	s.mu.Lock()
	if s.processing {
		s.mu.Unlock()
		return ErrHTMLRevisionWriterV1
	}
	s.processing = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.mu.Unlock() }()
	w.mu.Lock()
	if w.appendAttempted {
		w.mu.Unlock()
		return ErrHTMLRevisionWriterV1
	}
	w.appendAttempted = true
	w.mu.Unlock()
	previous, candidate := w.original, w.candidate
	// Repeat the shared exact original Append pre-write identity/summary/report
	// decisions against the final locked parent, preserving their original order.
	check, err := htmlmaterialization.PrepareAppendValidationV1(previous, candidate.document, htmlmaterialization.AppendInput{
		SourceJSON: candidate.sourceJSON, PageCount: candidate.pages, PreviousPageCount: candidate.previousPages, ActorID: w.stage.operation.actor,
		Summary: candidate.summary, MetadataRedactionReport: candidate.report})
	if err != nil {
		return err
	}
	// Preparation creates an opaque temporary current UUID only for validation.
	// Candidate's independently validated view has its OWN such temporary UUID.
	// Compare the complete proposed current source using a distinct fixed builder;
	// neither temporary UUID is used for row identity, DML or replay authority.
	proposed, err := w.validateFreshDocumentV1(check)
	if err != nil {
		return err
	}
	commitment, err := proposed.CommitmentV1()
	if err != nil {
		return err
	}
	before, err := w.source.validation.MaterializationDigestV1()
	if err != nil {
		return err
	}
	after, err := proposed.MaterializationDigestV1()
	if err != nil {
		return htmlmaterialization.ErrInvalid
	}
	if before == after {
		if candidate.document.PdfStorageKey.String == previous.PdfStorageKey.String && candidate.document.PdfStorageVersionID.String == previous.PdfStorageVersionID.String {
			return htmlmaterialization.ErrInvalid
		}
		// Only the original real request's immutable prepared input reaches here;
		// MaterializeRevisionV1 established the SAME optional-empty addition rule.
		// Its maps/source/PDF pins remain private and unchanged since that decision.
		if w.candidate.source.prepared == nil {
			return htmlmaterialization.ErrInvalid
		}
	}
	changed, err := proposed.ChangedSectionsV1()
	if err != nil {
		return err
	}
	parent := w.source.snapshot.current
	oldValidation := w.source.validation
	if parent == nil {
		previous, parent, oldValidation, err = w.registerOriginV1(call, previous)
		if err != nil {
			return err
		}
	}
	if parent.Sequence == math.MaxInt32 {
		return htmlmaterialization.ErrInvalid
	}
	oldCommitment, err := oldValidation.CommitmentV1()
	if err != nil {
		return err
	}
	oldDigest, err := hex.DecodeString(oldCommitment)
	if err != nil {
		return htmlmaterialization.ErrInvalid
	}
	if err = w.collections.acquireStatementV1(call, htmlRevisionSnapshotCaptureStageV1); err != nil {
		return err
	}
	snapshotID, err := w.queries.CaptureHTMLRevisionSnapshotIDV1(call, generated.CaptureHTMLRevisionSnapshotIDV1Params{
		DocumentID: previous.ID, OrgID: previous.OrgID, ExpectedUpdatedAt: previous.UpdatedAt, Kind: "draft_superseded", SourceCommitment: oldDigest,
		CreatedBy: pgtype.UUID{Bytes: w.stage.operation.actor, Valid: true}})
	if err != nil {
		return err
	}
	if snapshotID == uuid.Nil {
		return ErrHTMLRevisionWriterV1
	}
	// Measure ONLY this actual fresh capture under its genuine complete-context
	// capture+fresh-row loan. Missing old events/history are never repaired.
	if err = w.collections.acquireStatementV1(call, htmlRevisionSnapshotMeasureStageV1); err != nil {
		return err
	}
	measured, err := w.queries.MeasureHTMLRevisionSnapshotWireV1(call, generated.MeasureHTMLRevisionSnapshotWireV1Params{DocumentID: previous.ID, OrgID: previous.OrgID, SnapshotID: snapshotID})
	if err != nil {
		return err
	}
	if measured == nil || measured.DocumentID != previous.ID || measured.OrgID != previous.OrgID || measured.SnapshotID != snapshotID ||
		measured.MeasurementServerVersionNum != w.collections.header.ServerVersionNum {
		return ErrHTMLRevisionWriterV1
	}
	snapshotWire, err := htmlAuthoringSumV1(measured.SourceWireBytes, measured.FieldsWireBytes, measured.RecipientsWireBytes, measured.NoticeWireBytes, measured.CeremonyEventsWireBytes, measured.ReportWireBytes)
	if err != nil || snapshotWire > w.collections.components.freshSnapshotJSONBytes || measured.RawTextBytes < 0 || measured.RawTextBytes > w.collections.components.freshSnapshotRawBytes {
		return ErrHTMLRevisionWriterV1
	}
	origin, err := oldValidation.OriginCommitmentV1()
	if err != nil {
		return err
	}
	originDigest, err := hex.DecodeString(origin)
	if err != nil {
		return htmlmaterialization.ErrInvalid
	}
	digest, err := hex.DecodeString(commitment)
	if err != nil {
		return htmlmaterialization.ErrInvalid
	}
	row, err := w.queries.InsertHTMLDocumentMaterialization(call, generated.InsertHTMLDocumentMaterializationParams{
		DocumentID: previous.ID, OrgID: previous.OrgID, Sequence: parent.Sequence + 1, ParentID: pgtype.UUID{Bytes: parent.ID, Valid: true},
		ParentCommitment: bytes.Clone(parent.SourceCommitment), OriginCommitment: originDigest, SourceJson: bytes.Clone(candidate.sourceJSON), SourceCommitment: digest,
		PdfKey: candidate.document.PdfStorageKey.String, PdfSha256: bytes.Clone(candidate.document.PdfSha256), PdfVersionID: candidate.document.PdfStorageVersionID.String,
		PageCount: candidate.pages, Summary: candidate.summary, ChangedSections: changed, CreatedBy: w.stage.operation.actor, MetadataRedactionReport: bytes.Clone(candidate.report)})
	if err != nil {
		return err
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != previous.ID || row.OrgID != previous.OrgID || row.Sequence != parent.Sequence+1 {
		return ErrHTMLRevisionWriterV1
	}
	if err = w.collections.acquireStatementV1(call, htmlRevisionSnapshotClearStageV1); err != nil {
		return err
	}
	if _, err = w.queries.ClearUnsignedHTMLMaterializationFieldsOwnedV1(call, generated.ClearUnsignedHTMLMaterializationFieldsOwnedV1Params{DocumentID: previous.ID, OrgID: previous.OrgID, ExpectedUpdatedAt: previous.UpdatedAt}); err != nil {
		return err
	}
	if err = w.collections.acquireStatementV1(call, htmlRevisionSnapshotProjectStageV1); err != nil {
		return err
	}
	updated, err := w.queries.ProjectHTMLDocumentMaterialization(call, generated.ProjectHTMLDocumentMaterializationParams{
		DocumentID: previous.ID, OrgID: previous.OrgID, ExpectedUpdatedAt: previous.UpdatedAt, MaterializationID: row.ID})
	if err != nil {
		return err
	}
	validation, err := w.validateFreshProjectionV1(updated, row)
	if err != nil {
		return err
	}
	if !applicationContextV1(w.source.binding.ctx) {
		return ErrHTMLRevisionWriterV1
	}
	w.mu.Lock()
	w.updated = updated
	w.row = row
	w.validation = validation
	w.appended = true
	w.mu.Unlock()
	return nil
}
func (w *ApplicationHTMLRevisionWriterV1) validateFreshDocumentV1(doc *generated.Document) (*htmlsource.RevisionValidationV1, error) {
	s := w.source
	initial, err := s.initialDocumentComponentsV1(doc)
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(htmlRevisionSourceCandidateV1, 0, initial); err != nil {
		return nil, err
	}
	oldInput, oldMaster, oldOutput, oldScratch, oldCanonical, oldCanonicalScratch := s.effectiveInput, s.effectiveRawMaster, s.effectiveOutput, s.effectiveRawScratch, s.effectiveCanonical, s.effectiveCanonicalScratch
	validation, err := s.validateDocumentV1(doc)
	s.effectiveInput, s.effectiveRawMaster, s.effectiveOutput, s.effectiveRawScratch, s.effectiveCanonical, s.effectiveCanonicalScratch = oldInput, oldMaster, oldOutput, oldScratch, oldCanonical, oldCanonicalScratch
	return validation, err
}
func htmlRevisionKnownCurrentV1(row *generated.HtmlDocumentMaterialization) *htmlmaterialization.CurrentReadProjectionV1 {
	if row == nil {
		return nil
	}
	return &htmlmaterialization.CurrentReadProjectionV1{ID: row.ID, DocumentID: row.DocumentID, OrgID: row.OrgID, Sequence: row.Sequence, PageCount: row.PageCount,
		PdfKey: row.PdfKey, PdfVersionID: row.PdfVersionID, PdfSha256: row.PdfSha256, SourceCommitment: row.SourceCommitment, OriginCommitment: row.OriginCommitment,
		SourceJson: row.SourceJson, MetadataRedactionReport: row.MetadataRedactionReport}
}
func (w *ApplicationHTMLRevisionWriterV1) validateFreshProjectionV1(doc *generated.Document, row *generated.HtmlDocumentMaterialization) (*htmlsource.RevisionValidationV1, error) {
	if doc == nil || doc.ID != w.stage.operation.document || doc.OrgID != w.stage.operation.org {
		return nil, ErrHTMLRevisionWriterV1
	}
	validation, err := w.validateFreshDocumentV1(doc)
	if err != nil {
		return nil, err
	}
	projection := htmlRevisionKnownCurrentV1(row)
	required, err := htmlmaterialization.ValidateCurrentReadProjectionMetadataPreparedV1(doc, projection, validation)
	if err != nil {
		return nil, err
	}
	if !required {
		return nil, htmlmaterialization.ErrInvalid
	}
	rowValidation := validation
	if !bytes.Equal(doc.HtmlCurrentSourceJson, projection.SourceJson) {
		actual := *doc
		actual.HtmlCurrentSourceJson = projection.SourceJson
		rowValidation, err = w.validateFreshDocumentV1(&actual)
		if err != nil {
			return nil, htmlRevisionCurrentValidationErrorV1(err)
		}
	}
	if err = htmlmaterialization.ValidateCurrentReadProjectionPreparedV1(doc, projection, validation, rowValidation); err != nil {
		return nil, err
	}
	return validation, nil
}

// Exact original legacy RegisterOrigin writes under this SAME real writer.
// The source/report/changed-section decisions use immutable prepared results;
// no complete old materialization/history body is loaded or guessed.
func (w *ApplicationHTMLRevisionWriterV1) registerOriginV1(call context.Context, doc *generated.Document) (*generated.Document, *htmlmaterialization.CurrentReadProjectionV1, *htmlsource.RevisionValidationV1, error) {
	if err := htmlmaterialization.PrepareOriginValidationV1(doc, w.candidate.previousPages, w.stage.operation.actor); err != nil {
		return nil, nil, nil, err
	}
	commitment, err := w.source.validation.CommitmentV1()
	if err != nil {
		return nil, nil, nil, err
	}
	digest, err := hex.DecodeString(commitment)
	if err != nil {
		return nil, nil, nil, htmlmaterialization.ErrInvalid
	}
	changed, err := w.source.validation.ChangedSectionsV1()
	if err != nil {
		return nil, nil, nil, err
	}
	// Legacy first projection is a genuine new row producer. Its bounded source,
	// report and full row were included in NewWriter's retained fresh-output loan.
	row, err := w.queries.InsertHTMLDocumentMaterialization(call, generated.InsertHTMLDocumentMaterializationParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, Sequence: 1, OriginCommitment: digest, SourceJson: bytes.Clone(doc.HtmlSourceJson), SourceCommitment: digest,
		PdfKey: doc.PdfStorageKey.String, PdfSha256: bytes.Clone(doc.PdfSha256), PdfVersionID: doc.PdfStorageVersionID.String, PageCount: w.candidate.previousPages,
		Summary: "Original HTML materialization", ChangedSections: changed, CreatedBy: w.stage.operation.actor, MetadataRedactionReport: bytes.Clone(doc.MetadataRedactionReport)})
	if err != nil {
		return nil, nil, nil, err
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != doc.ID || row.OrgID != doc.OrgID || row.Sequence != 1 {
		return nil, nil, nil, ErrHTMLRevisionWriterV1
	}
	if err = w.collections.acquireStatementV1(call, htmlRevisionSnapshotOriginProjectStageV1); err != nil {
		return nil, nil, nil, err
	}
	updated, err := w.queries.ProjectHTMLDocumentMaterialization(call, generated.ProjectHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: doc.OrgID, ExpectedUpdatedAt: doc.UpdatedAt, MaterializationID: row.ID})
	if err != nil {
		return nil, nil, nil, err
	}
	validation, err := w.validateFreshProjectionV1(updated, row)
	if err != nil {
		return nil, nil, nil, err
	}
	return updated, htmlRevisionKnownCurrentV1(row), validation, nil
}
