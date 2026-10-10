-- name: InsertHTMLDocumentMaterialization :one
INSERT INTO html_document_materializations (
    document_id, org_id, sequence, parent_id, parent_commitment, origin_commitment,
    source_json, source_commitment, pdf_key, pdf_sha256, pdf_version_id, page_count,
    summary, changed_sections, created_by, metadata_redaction_report
) VALUES (
    sqlc.arg(document_id), sqlc.arg(org_id), sqlc.arg(sequence), sqlc.narg(parent_id), sqlc.narg(parent_commitment), sqlc.arg(origin_commitment),
    sqlc.arg(source_json)::jsonb, sqlc.arg(source_commitment), sqlc.arg(pdf_key), sqlc.arg(pdf_sha256), sqlc.arg(pdf_version_id), sqlc.arg(page_count),
    sqlc.arg(summary), sqlc.arg(changed_sections)::text[], sqlc.arg(created_by), sqlc.narg(metadata_redaction_report)::jsonb
) RETURNING *;

-- name: GetHTMLDocumentMaterialization :one
SELECT * FROM html_document_materializations
WHERE document_id = sqlc.arg(document_id) AND org_id = sqlc.arg(org_id) AND sequence = sqlc.arg(sequence);

-- name: GetCurrentHTMLDocumentMaterialization :one
SELECT m.* FROM html_document_materializations m JOIN documents d
    ON d.html_current_materialization_id = m.id AND d.id = m.document_id AND d.org_id = m.org_id
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id);

-- name: ListHTMLDocumentMaterializations :many
-- Bounded lists never duplicate inline masters/assets.
SELECT m.id, m.document_id, m.org_id, m.sequence, m.source_commitment, m.pdf_sha256,
       m.page_count, m.summary, m.changed_sections, m.created_by, m.created_at,
       (d.html_current_materialization_id = m.id)::boolean AS is_current
FROM html_document_materializations m JOIN documents d ON d.id = m.document_id AND d.org_id = m.org_id
WHERE m.document_id = sqlc.arg(document_id) AND m.org_id = sqlc.arg(org_id)
ORDER BY m.sequence DESC LIMIT sqlc.arg(row_limit)::integer;

-- name: ProjectHTMLDocumentMaterialization :one
UPDATE documents d SET
    html_current_materialization_id = m.id, html_current_source_json = m.source_json,
    html_current_materialization_sequence = m.sequence, html_current_page_count = m.page_count,
    pdf_storage_key = m.pdf_key, pdf_sha256 = m.pdf_sha256, pdf_storage_version_id = m.pdf_version_id,
    metadata_redaction_report = COALESCE(m.metadata_redaction_report, '{}'::jsonb),
    variables_json = m.source_json -> 'values', evidence_version_pins_required = true,
    rendered_pdf_key = NULL, rendered_pdf_sha = NULL, rendered_pdf_version_id = NULL,
    updated_at = clock_timestamp()
FROM html_document_materializations m
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.status = 'draft' AND d.deleted_at IS NULL AND d.source_kind = 'pdf'
    AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
    AND m.id = sqlc.arg(materialization_id) AND m.document_id = d.id AND m.org_id = d.org_id
    AND ((m.sequence = 1 AND d.html_current_materialization_id IS NULL)
         OR m.parent_id = d.html_current_materialization_id)
RETURNING d.*;

-- name: ClearUnsignedHTMLMaterializationFields :execrows
-- Parent is locked by the caller. The statement separately refuses captured
-- data so a future caller cannot cascade-delete a signature or filled field.
-- Deletion also requires the exact current layout/context to be archived first.
DELETE FROM document_fields f USING documents d
WHERE f.document_id = d.id AND d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.status = 'draft' AND d.deleted_at IS NULL
    AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
    AND EXISTS (SELECT 1 FROM html_document_materialization_snapshots s
        CROSS JOIN LATERAL hash_html_materialization_snapshot_context(d.id) c
        WHERE s.document_id = d.id AND s.org_id = d.org_id AND s.kind = 'draft_superseded'
            AND s.captured_updated_at = d.updated_at
            AND s.materialization_id IS NOT DISTINCT FROM d.html_current_materialization_id
            AND s.source_json IS NOT DISTINCT FROM COALESCE(d.html_current_source_json, d.html_source_json)
            AND s.pdf_key IS NOT DISTINCT FROM d.pdf_storage_key AND s.pdf_sha256 IS NOT DISTINCT FROM d.pdf_sha256
            AND s.pdf_version_id IS NOT DISTINCT FROM d.pdf_storage_version_id
            AND s.metadata_redaction_report IS NOT DISTINCT FROM d.metadata_redaction_report
            AND s.reviewed_pdf_sha256 IS NOT DISTINCT FROM d.html_reviewed_pdf_sha256
            AND s.reviewed_by IS NOT DISTINCT FROM d.html_reviewed_by AND s.reviewed_at IS NOT DISTINCT FROM d.html_reviewed_at
            AND s.fields_json IS NOT DISTINCT FROM c.fields_json AND s.recipients_json IS NOT DISTINCT FROM c.recipients_json
            AND s.notice_context_json IS NOT DISTINCT FROM c.notice_context_json AND s.ceremony_events_json IS NOT DISTINCT FROM c.ceremony_events_json)
    AND NOT EXISTS (SELECT 1 FROM signatures s WHERE s.document_id = d.id)
    AND NOT EXISTS (SELECT 1 FROM recipients r WHERE r.document_id = d.id AND (r.status IN ('signed','accepted') OR r.signed_at IS NOT NULL))
    AND NOT EXISTS (SELECT 1 FROM document_fields filled WHERE filled.document_id = d.id AND (filled.value IS NOT NULL OR filled.completed_at IS NOT NULL));

-- name: CaptureHTMLMaterializationSnapshot :one
-- Capture BEFORE draft reset/projection. No new-clock retention extension:
-- only the committed old epoch/started intent/finalization deadline is used.
INSERT INTO html_document_materialization_snapshots (
    document_id, org_id, materialization_id, kind, captured_updated_at, source_json, source_commitment,
    pdf_key, pdf_sha256, pdf_version_id, page_count,
    rendered_pdf_key, rendered_pdf_sha256, rendered_pdf_version_id,
    reviewed_pdf_sha256, reviewed_by, reviewed_at,
    fields_json, recipients_json, notice_context_json, ceremony_events_json,
    notice_epoch_at, retain_until, created_by, metadata_redaction_report
)
SELECT d.id, d.org_id, d.html_current_materialization_id, sqlc.arg(kind)::text,
    d.updated_at, COALESCE(d.html_current_source_json, d.html_source_json), sqlc.arg(source_commitment)::bytea,
    d.pdf_storage_key, d.pdf_sha256, d.pdf_storage_version_id, d.html_current_page_count,
    d.rendered_pdf_key, d.rendered_pdf_sha, d.rendered_pdf_version_id,
    d.html_reviewed_pdf_sha256, d.html_reviewed_by, d.html_reviewed_at,
    c.fields_json, c.recipients_json, c.notice_context_json, c.ceremony_events_json,
    CASE WHEN sqlc.arg(kind)::text = 'ceremony_retired' THEN d.article13_notice_epoch_at ELSE NULL END,
    CASE WHEN sqlc.arg(kind)::text = 'ceremony_retired' THEN GREATEST(d.finalization_retain_until,
        hash_evidence_retain_until(d.article13_notice_epoch_at, 7),
        (SELECT max(si.retain_until) FROM send_sealing_intents si WHERE si.document_id = d.id AND si.retention_started_at IS NOT NULL)) ELSE NULL END,
    sqlc.narg(created_by)::uuid, d.metadata_redaction_report
FROM documents d
CROSS JOIN LATERAL hash_html_materialization_snapshot_context(d.id) c
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.html_source_json IS NOT NULL AND d.deleted_at IS NULL
    AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
    AND ((sqlc.arg(kind)::text = 'draft_superseded' AND d.status = 'draft')
        OR (sqlc.arg(kind)::text = 'ceremony_retired' AND d.status = 'changes_requested'))
RETURNING *;
