// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

// PinPreSignBaseV1 is the fixed post-AppendAtomic native mutation. The
// execution already binds the actual immutable base version; this enables the
// existing all-version Send guard without resolving latest or adding objects.
func (w *ApplicationHTMLSendWorkV1) PinPreSignBaseV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLPreSignCommitV1 || w.sourceDocument == nil || w.sourceDocument.Status != "draft" || !w.intentCreated || w.pinsAttempted {
		return ErrHTMLSendWorkV1
	}
	w.pinsAttempted = true
	d := w.sourceDocument
	if !d.PdfStorageVersionID.Valid || d.PdfStorageVersionID.String == "" || d.RenderedPdfKey.Valid || d.RenderedPdfVersionID.Valid || len(d.RenderedPdfSha) != 0 {
		return ErrHTMLSendWorkV1
	}
	var exact bool
	db := &applicationOwnedDBTXV1{session: w.session.state}
	err := db.QueryRow(call, `SELECT EXISTS(SELECT 1 FROM presign_executions e JOIN send_sealing_intents i ON i.org_id=e.org_id AND i.document_id=e.document_id AND i.presign_execution_id=e.id
  WHERE e.org_id=$1 AND e.document_id=$2
  AND convert_from(e.canonical_execution,'UTF8')::jsonb#>>'{document,base_pdf,artifact,storage_key}'=$3
  AND convert_from(e.canonical_execution,'UTF8')::jsonb#>>'{document,base_pdf,artifact,version_id}'=$4
  AND convert_from(e.canonical_execution,'UTF8')::jsonb#>>'{document,base_pdf,artifact,sha256}'=encode($5::bytea,'hex'))`, d.OrgID, d.ID, d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256).Scan(&exact)
	if err != nil || !exact {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("sealing")))
	if err != nil {
		return err
	}
	row, err := w.queries.PinDocumentSendEvidenceVersions(call, generated.PinDocumentSendEvidenceVersionsParams{ID: d.ID, OrgID: d.OrgID, PdfStorageVersionID: d.PdfStorageVersionID, RenderedPdfVersionID: pgtype.Text{}})
	if err != nil {
		return err
	}
	if !w.verifyDocumentReturnV1(row, raw) || row.Status != "sealing" || !row.EvidenceVersionPinsRequired {
		return ErrHTMLSendWorkV1
	}
	before, after := *d, *row
	before.Status = after.Status
	before.EvidenceVersionPinsRequired = after.EvidenceVersionPinsRequired
	before.UpdatedAt = after.UpdatedAt
	if w.confirmedBasisValid {
		before.LawfulBasis = w.confirmedBasis
	}
	if !htmlSendDocumentExactTupleEqualV1(&before, &after) || before.ParticipantReportSchema != after.ParticipantReportSchema {
		return ErrHTMLSendWorkV1
	}
	w.pinsCompleted = true
	return nil
}
