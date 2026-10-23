// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This fixed header is read only by the actual signer owner, after its scalar
// candidate/credential locks and before the complete model/body loan. The two
// bytea lengths bound all SQL JSON work and the retained scalar projection.
// There is deliberately NO read/lock of the completed original document: the
// relation already captured and made its original pins immutable at linking.
type applicationSignerAmendmentHeaderV1 struct {
	id        uuid.UUID
	raw, wire int64
}

func (r *ApplicationSignerReaderV1) signerAmendmentHeaderV1(ctx context.Context, db generated.DBTX) (*applicationSignerAmendmentHeaderV1, error) {
	if r == nil || r.self != r || !r.read || r.consumerClosed || r.released {
		return nil, ErrSignerReadV1
	}
	var h applicationSignerAmendmentHeaderV1
	var pins, files, name int64
	err := db.QueryRow(ctx, `SELECT id,octet_length(original_pins)::bigint,octet_length(file_set)::bigint,
 COALESCE(octet_length(convert_from(original_pins,'UTF8')::jsonb->>'original_name'),0)::bigint
 FROM document_amendments_v1 WHERE org_id=$1 AND document_id=$2`, r.scope.org, r.scope.document).Scan(&h.id, &pins, &files, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if h.id == uuid.Nil || pins < 2 || pins > 32768 || files < 2 || files > 65536 || name < 1 || name > 512 {
		return nil, ErrSignerReadV1
	}
	h.wire = pins + files
	h.raw = name + 1024 // Fixed UUID/digest/mode projection and copies.
	return &h, nil
}
func (r *ApplicationSignerReaderV1) signerAmendmentBodyV1(ctx context.Context, db generated.DBTX, h *applicationSignerAmendmentHeaderV1, doc *generated.Document) (*amendments.SignerContextV1, error) {
	if h == nil {
		return nil, nil
	}
	if r == nil || r.self != r || !r.read || r.consumerClosed || r.released || doc == nil || doc.ID != r.scope.document || doc.OrgID != r.scope.org || !doc.PdfStorageKey.Valid || !doc.PdfStorageVersionID.Valid || len(doc.PdfSha256) != 32 {
		return nil, ErrSignerReadV1
	}
	c := &amendments.SignerContextV1{Schema: amendments.SignerContextSchemaV1}
	var valid bool
	err := db.QueryRow(ctx, `SELECT a.id,a.revision::text,a.document_id,a.original_document_id,p->>'original_name',
 p->'final_pdf'->>'sha256',p->>'report_sha256',p->'report_pdf'->>'sha256',a.mode,encode(a.file_commitment_sha256,'hex'),
 COALESCE(a.original_pins_sha256=sha256(a.original_pins)
 AND a.file_commitment_sha256=sha256(convert_to('hash:later-amendment-files:v1','UTF8')||decode('00','hex')||a.file_set)
 AND p->>'document_id'=a.original_document_id::text
 AND f->>'schema'='hash-amendment-files-v1' AND f->>'document_id'=a.document_id::text
 AND f->'files'->0->>'position'='0' AND f->'files'->0->>'document_id'=a.document_id::text
 AND f->'files'->0->>'key'=$5 AND f->'files'->0->>'version_id'=$6
 AND f->'files'->0->>'sha256'=encode($7::bytea,'hex')
 AND f->>'source_commitment_sha256'=COALESCE(COALESCE(d.html_current_source_json,d.html_source_json)->>'commitment',''),FALSE)
 FROM document_amendments_v1 a
 JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
 CROSS JOIN LATERAL (SELECT convert_from(a.original_pins,'UTF8')::jsonb p,convert_from(a.file_set,'UTF8')::jsonb f) saved
 WHERE a.org_id=$1 AND a.document_id=$2 AND a.id=$3
 AND octet_length(a.original_pins)+octet_length(a.file_set)=$4
 AND octet_length(p->>'original_name')=$8`, r.scope.org, r.scope.document, h.id, h.wire, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256, h.raw-1024).Scan(&c.AmendmentID, &c.Revision, &c.DocumentID, &c.OriginalDocumentID, &c.OriginalName, &c.OriginalFinalPDFSHA256, &c.OriginalReportSHA256, &c.OriginalReportPDFSHA256, &c.Mode, &c.FileCommitmentSHA256, &valid)
	if err != nil {
		return nil, err
	}
	if !valid || c.ValidateV1(doc.ID, doc.RequiresSignature) != nil {
		return nil, ErrSignerReadV1
	}
	return c, nil
}
