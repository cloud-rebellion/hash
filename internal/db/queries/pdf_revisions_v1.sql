-- name: InsertDocumentPDFRevisionV1 :one
INSERT INTO document_pdf_revisions_v1 (
    id, org_id, document_id, sequence, parent_id,
    previous_pdf_key, previous_pdf_sha256, previous_pdf_version_id,
    pdf_key, pdf_sha256, pdf_version_id, page_count, metadata_redaction_report,
    fields_json, recipients_json, summary, created_by)
VALUES (
    sqlc.arg(id)::uuid, sqlc.arg(org_id)::uuid, sqlc.arg(document_id)::uuid, sqlc.arg(sequence)::int, sqlc.narg(parent_id)::uuid,
    sqlc.arg(previous_pdf_key)::text, sqlc.arg(previous_pdf_sha256)::bytea, sqlc.arg(previous_pdf_version_id)::text,
    sqlc.arg(pdf_key)::text, sqlc.arg(pdf_sha256)::bytea, sqlc.arg(pdf_version_id)::text, sqlc.arg(page_count)::int,
    sqlc.arg(metadata_redaction_report)::jsonb,
    (SELECT c.fields_json FROM hash_html_materialization_snapshot_context(sqlc.arg(document_id)::uuid) c),
    (SELECT c.recipients_json FROM hash_html_materialization_snapshot_context(sqlc.arg(document_id)::uuid) c),
    sqlc.arg(summary)::text, sqlc.arg(created_by)::uuid)
RETURNING *;

-- name: GetLatestDocumentPDFRevisionV1 :one
SELECT * FROM document_pdf_revisions_v1
WHERE document_id = $1 AND org_id = $2
ORDER BY sequence DESC LIMIT 1;

-- name: GetDocumentPDFRevisionBySequenceV1 :one
SELECT * FROM document_pdf_revisions_v1
WHERE document_id = $1 AND org_id = $2 AND sequence = $3;

-- name: ListDocumentPDFRevisionsV1 :many
SELECT r.*, (v.reviewed_by IS NOT NULL)::boolean AS reviewed, COALESCE(v.reviewer_kind, '')::text AS review_kind, v.reviewed_by AS review_by, v.created_at AS review_at
FROM document_pdf_revisions_v1 r
LEFT JOIN LATERAL (SELECT x.reviewer_kind, x.reviewed_by, x.created_at FROM document_pdf_reviews_v1 x
                   WHERE x.revision_id = r.id ORDER BY (x.reviewer_kind = 'human') DESC, x.created_at DESC LIMIT 1) v ON true
WHERE r.document_id = $1 AND r.org_id = $2
ORDER BY r.sequence DESC
LIMIT 200;

-- name: InsertDocumentPDFReviewV1 :one
INSERT INTO document_pdf_reviews_v1 (id, org_id, document_id, revision_id, pdf_sha256, reviewer_kind, reviewed_by, visually_reviewed, reviewed_pages)
VALUES (sqlc.arg(id)::uuid, sqlc.arg(org_id)::uuid, sqlc.arg(document_id)::uuid, sqlc.arg(revision_id)::uuid,
        sqlc.arg(pdf_sha256)::bytea, sqlc.arg(reviewer_kind)::text, sqlc.arg(reviewed_by)::uuid,
        sqlc.arg(visually_reviewed)::boolean, sqlc.arg(reviewed_pages)::int)
RETURNING *;

-- name: ListDocumentPDFErasureScopeV1 :many
-- A small exact revision projection for the destructive-erasure confirmation.
-- Caller holds the parent privacy lock and checks the complete row count.
-- The extra row detects an over-limit inventory; no fields/recipient snapshots
-- or document content enter this confirmation projection.
SELECT id, sequence, previous_pdf_key, previous_pdf_sha256, previous_pdf_version_id,
       pdf_key, pdf_sha256, pdf_version_id
FROM document_pdf_revisions_v1
WHERE document_id = $1 AND org_id = $2
ORDER BY sequence, id
LIMIT 201;

-- name: GetDocumentPDFReviewV1 :one
SELECT * FROM document_pdf_reviews_v1 WHERE revision_id = $1 AND org_id = $2;

-- name: InsertDocumentReviewKindV1 :one
-- Records who performed the document's current HTML review, in the review's own
-- transaction. The database refuses an agent kind for a signing document.
INSERT INTO document_review_kinds_v1 (id, org_id, document_id, subject_id, pdf_sha256, reviewer_kind, reviewed_by)
SELECT sqlc.arg(id)::uuid, d.org_id, d.id, COALESCE(d.html_current_materialization_id, d.id), d.html_reviewed_pdf_sha256,
       sqlc.arg(reviewer_kind)::text, d.html_reviewed_by
FROM documents d
WHERE d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
  AND d.html_reviewed_pdf_sha256 IS NOT NULL AND d.html_reviewed_by IS NOT NULL
RETURNING *;

-- name: GetLatestDocumentReviewKindV1 :one
SELECT k.* FROM document_review_kinds_v1 k JOIN documents d ON d.id = k.document_id AND d.org_id = k.org_id
WHERE d.id = $1 AND d.org_id = $2 AND k.subject_id = COALESCE(d.html_current_materialization_id, d.id)
  AND k.pdf_sha256 = d.html_reviewed_pdf_sha256
ORDER BY k.created_at DESC, k.id DESC LIMIT 1;
