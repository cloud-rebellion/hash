-- Owned complete HTML revision field retirement. Query-only native foundation.
-- The fixed native owner must hold actual M94 parent->subject->orgchain and
-- admitted complete source/field/recipient/notice/event/history resources first.
-- MATERIALIZED computes the unchanged canonical context at most once for this
-- exact scoped parent, rather than leaving it correlated with fields/history.
-- No immutable history is removed or selected with LIMIT.

-- name: ClearUnsignedHTMLMaterializationFieldsOwnedV1 :execrows
WITH parent AS MATERIALIZED (
 SELECT p.id,p.org_id FROM documents p
 WHERE p.id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid
  AND p.status='draft' AND p.deleted_at IS NULL
  AND p.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 FOR UPDATE OF p
), canonical_context AS MATERIALIZED (
 SELECT p.id AS document_id,c.fields_json,c.recipients_json,c.notice_context_json,c.ceremony_events_json
 FROM parent p CROSS JOIN LATERAL hash_html_materialization_snapshot_context(p.id) AS c(fields_json,recipients_json,notice_context_json,ceremony_events_json)
)
DELETE FROM document_fields f USING documents d
WHERE f.document_id = d.id AND d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
    AND d.status = 'draft' AND d.deleted_at IS NULL
    AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
    AND EXISTS (SELECT 1 FROM html_document_materialization_snapshots s
        CROSS JOIN canonical_context c
        WHERE c.document_id = d.id AND s.document_id = d.id AND s.org_id = d.org_id AND s.kind = 'draft_superseded'
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


-- name: GetHTMLRevisionLatestVersionIdentityV1 :one
-- Fixed owned revision caller retains the real scoped parent UPDATE, reads the
-- original latest-number scalar first, then obtains ONLY its needed identity.
-- Preserve original document subject/order exactly: do not hide an existing
-- cross-org latest version by adding an org filter. The native owner must check
-- the returned document/org/version against its original actual parent and
-- latest-number observation, and refuse disagreement before any INSERT.
-- No old version JSON, name, summary or source is fetched or repaired.
SELECT v.id,v.document_id,v.org_id,v.version_no
FROM document_versions v
WHERE v.document_id=sqlc.arg(document_id)::uuid
ORDER BY v.version_no DESC
LIMIT 1;
