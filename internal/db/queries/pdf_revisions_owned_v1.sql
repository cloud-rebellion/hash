-- name: GetPDFRevisionBlockersV1 :one
-- Caller holds the parent lock. Friendly refusals ahead of the M124 triggers.
SELECT d.source_kind::text AS source_kind, d.is_envelope AS is_envelope,
       (d.parent_envelope_id IS NOT NULL)::boolean AS in_envelope,
       (d.template_id IS NOT NULL)::boolean AS template_backed,
       (d.html_source_json IS NOT NULL)::boolean AS html_source,
       EXISTS (SELECT 1 FROM document_amendments_v1 a WHERE a.document_id = d.id AND a.org_id = d.org_id)::boolean AS amendment_linked
FROM documents d
WHERE d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL;

-- name: ClearDraftFieldsForPDFRevisionV1 :execrows
-- Runs after the revision row archived the field layout. Evidence-bearing drafts
-- were refused before this point.
DELETE FROM document_fields f USING documents d
WHERE f.document_id = d.id AND d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
  AND d.status = 'draft' AND d.deleted_at IS NULL
  AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
  AND f.value IS NULL AND f.completed_at IS NULL;

-- name: ProjectPDFRevisionV1 :one
UPDATE documents d SET
    pdf_storage_key = r.pdf_key, pdf_sha256 = r.pdf_sha256, pdf_storage_version_id = r.pdf_version_id,
    metadata_redaction_report = r.metadata_redaction_report, evidence_version_pins_required = true,
    rendered_pdf_key = NULL, rendered_pdf_sha = NULL, rendered_pdf_version_id = NULL,
    updated_at = clock_timestamp()
FROM document_pdf_revisions_v1 r
WHERE d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
  AND d.status = 'draft' AND d.deleted_at IS NULL AND d.source_kind = 'pdf'
  AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
  AND r.id = sqlc.arg(revision_id)::uuid AND r.document_id = d.id AND r.org_id = d.org_id
RETURNING d.*;

-- name: TouchDocumentForPDFReviewV1 :one
-- A review changes what a stale tab may do next, so it moves the pin.
UPDATE documents SET updated_at = clock_timestamp()
WHERE id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  AND status = 'draft' AND deleted_at IS NULL AND updated_at = sqlc.arg(expected_updated_at)::timestamptz
RETURNING *;

-- name: GetPDFReviewStateV1 :one
-- No row means the document never had a replaced PDF, so nothing is gated.
-- reviewed: any review of the latest revision; human_reviewed: a human one.
SELECT r.id AS revision_id, r.sequence AS sequence, r.pdf_sha256 AS pdf_sha256, r.page_count AS page_count,
       EXISTS (SELECT 1 FROM document_pdf_reviews_v1 v WHERE v.revision_id = r.id)::boolean AS reviewed,
       EXISTS (SELECT 1 FROM document_pdf_reviews_v1 v WHERE v.revision_id = r.id AND v.reviewer_kind = 'human')::boolean AS human_reviewed
FROM document_pdf_revisions_v1 r
WHERE r.document_id = sqlc.arg(document_id)::uuid AND r.org_id = sqlc.arg(org_id)::uuid
ORDER BY r.sequence DESC LIMIT 1;

-- name: RequirePDFBytesReviewedV1 :exec
-- The shared review gate (M124). Raises 23514 when a replaced PDF is unreviewed.
SELECT hash_pdf_bytes_reviewed_v1(sqlc.arg(document_id)::uuid);

-- name: CountDocumentPDFRevisionsV1 :one
SELECT count(*)::int FROM document_pdf_revisions_v1 WHERE document_id = $1 AND org_id = $2;
