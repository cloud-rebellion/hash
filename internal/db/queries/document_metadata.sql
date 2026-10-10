-- Read-only document projections. Inline approved/origin/current HTML designs
-- can contain large assets. Lists and identity guards must not transfer them
-- from PostgreSQL merely to discard them during JSON serialization. Full
-- GetDocument/locked reads remain authoritative for rendering and evidence.

-- name: ListDocumentMetadataForREST :many
SELECT d.id, d.org_id, d.template_id, d.name, d.status, d.routing_mode,
    d.source_kind, d.requires_signature, d.blocks_json, d.variables_json,
    d.pdf_storage_key, d.pdf_sha256, d.final_pdf_key, d.final_pdf_sha,
    d.audit_cert_key, d.expires_at, d.sent_at, d.completed_at, d.sender_id,
    d.metadata, d.default_locale, d.created_at, d.updated_at,
    d.parent_envelope_id, d.envelope_position, d.is_envelope,
    (d.html_source_json IS NOT NULL)::boolean AS has_html_source,
    (d.html_source_json IS NOT NULL AND (
        d.html_reviewed_by IS NULL OR d.html_reviewed_at IS NULL
        OR d.pdf_sha256 IS NULL OR octet_length(d.pdf_sha256) <> 32
        OR d.html_reviewed_pdf_sha256 IS DISTINCT FROM d.pdf_sha256
        OR (d.html_current_materialization_id IS NOT NULL
            AND d.html_reviewed_materialization_id IS DISTINCT FROM d.html_current_materialization_id)
    ))::boolean AS html_review_required,
    d.html_current_materialization_sequence, d.html_effective_source_commitment
FROM documents d
WHERE d.org_id = $1
  AND d.deleted_at IS NULL
  AND ($2::TEXT[] IS NULL OR d.status = ANY($2::TEXT[]))
ORDER BY d.updated_at DESC
LIMIT $3 OFFSET $4;

-- name: ListEnvelopeChildMetadataForRead :many
-- Match the existing child-list predicate/order; do not change lifecycle or
-- deleted-child semantics as part of this projection-only read path.
SELECT d.id, d.org_id, d.template_id, d.name, d.status, d.routing_mode,
    d.source_kind, d.requires_signature, d.blocks_json, d.variables_json,
    d.pdf_storage_key, d.pdf_sha256, d.final_pdf_key, d.final_pdf_sha,
    d.audit_cert_key, d.expires_at, d.sent_at, d.completed_at, d.sender_id,
    d.metadata, d.default_locale, d.created_at, d.updated_at,
    d.parent_envelope_id, d.envelope_position, d.is_envelope,
    (d.html_source_json IS NOT NULL)::boolean AS has_html_source,
    (d.html_source_json IS NOT NULL AND (
        d.html_reviewed_by IS NULL OR d.html_reviewed_at IS NULL
        OR d.pdf_sha256 IS NULL OR octet_length(d.pdf_sha256) <> 32
        OR d.html_reviewed_pdf_sha256 IS DISTINCT FROM d.pdf_sha256
        OR (d.html_current_materialization_id IS NOT NULL
            AND d.html_reviewed_materialization_id IS DISTINCT FROM d.html_current_materialization_id)
    ))::boolean AS html_review_required,
    d.html_current_materialization_sequence, d.html_effective_source_commitment
FROM documents d
WHERE d.parent_envelope_id = $1 AND d.org_id = $2
ORDER BY d.envelope_position ASC NULLS LAST, d.created_at ASC;

-- name: GetDocumentReadProjection :one
-- This row retains the ordinary Document shape for scoped MCP list/search.
-- Both master columns are SQL NULL, not synthetic source JSON.
SELECT d.id, d.org_id, d.template_id, d.name,
    d.status, d.routing_mode, d.source_kind, d.blocks_json,
    d.variables_json, d.rendered_pdf_key, d.rendered_pdf_sha, d.pdf_storage_key,
    d.pdf_sha256, d.final_pdf_key, d.final_pdf_sha, d.audit_cert_key,
    d.expires_at, d.sent_at, d.completed_at, d.sender_id,
    d.metadata, d.created_at, d.updated_at, d.parent_envelope_id,
    d.envelope_position, d.is_envelope, d.metadata_redaction_report, d.routing_tier,
    d.negotiation_enabled, d.bilingual_target_lang, d.lawful_basis, d.deleted_at,
    d.default_locale, d.requires_signature, d.audit_payload_key, d.audit_payload_sha256,
    d.audit_signature_key, d.audit_signature_sha256, d.pdf_storage_version_id, d.rendered_pdf_version_id,
    d.final_pdf_version_id, d.audit_cert_sha256, d.audit_cert_version_id, d.audit_payload_version_id,
    d.audit_signature_version_id, d.evidence_version_pins_required, d.completion_effective_at, d.completion_effective_at_bound,
    d.finalization_retain_until, d.article13_notice_epoch_at, d.article13_notice_schema, d.article13_notice_epoch_v61_committed,
    NULL::jsonb AS html_source_json, d.html_reviewed_pdf_sha256, d.html_reviewed_by, d.html_reviewed_at,
    d.html_current_materialization_id, NULL::jsonb AS html_current_source_json, d.html_current_page_count, d.html_current_materialization_sequence,
    d.html_reviewed_materialization_id, d.html_effective_source_commitment
FROM documents d
WHERE d.id = $1 AND d.org_id = $2 AND d.deleted_at IS NULL;

-- name: GetActiveDocumentIdentity :one
-- Membership-only read. Callers must not use this in content validation,
-- authoring, rendering, signature or retained-history integrity paths.
SELECT id FROM documents
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;
