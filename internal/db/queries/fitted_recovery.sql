-- Read-only recovery projections. The journal/manifests supply original names,
-- fonts and field values. Do not copy mutable names, HTML sources, JSON bodies,
-- network metadata or UA strings through these identity queries. Caller still
-- requires physical session/owner reconciliation and global resource admission.

-- name: GetFittedFinalizationRecoveryDocumentMetadata :one
SELECT d.id, d.org_id, d.status, d.source_kind, d.requires_signature,
    d.is_envelope, d.parent_envelope_id, d.deleted_at, d.sent_at, d.completed_at,
    d.pdf_storage_key, d.pdf_storage_version_id, d.pdf_sha256,
    d.evidence_version_pins_required,
    d.article13_notice_epoch_at, d.article13_notice_epoch_v61_committed,
    d.completion_effective_at, d.completion_effective_at_bound,
    d.finalization_retain_until, d.signature_fit_reserved_bytes,
    d.fits_index_required, d.fits_index_preparation_id,
    d.fits_index_storage_key, d.fits_index_version_id, d.fits_index_sha256, d.fits_index_bytes,
    d.final_pdf_key, d.final_pdf_version_id, d.final_pdf_sha,
    d.audit_cert_key, d.audit_cert_version_id, d.audit_cert_sha256,
    d.audit_payload_key, d.audit_payload_version_id, d.audit_payload_sha256,
    d.audit_signature_key, d.audit_signature_version_id, d.audit_signature_sha256
FROM documents d
WHERE d.id = sqlc.arg(id) AND d.org_id = sqlc.arg(org_id)
    -- An older repeatable/serializable snapshot could hide an already committed
    -- output reservation even after acquiring the unchanged document row lock.
    AND current_setting('transaction_isolation') = 'read committed'
    AND octet_length(d.status) <= 32 AND octet_length(d.source_kind) <= 32
    AND (d.pdf_storage_key IS NULL OR octet_length(d.pdf_storage_key) <= 1024)
    AND (d.pdf_storage_version_id IS NULL OR octet_length(d.pdf_storage_version_id) <= 1024)
    AND (d.pdf_sha256 IS NULL OR octet_length(d.pdf_sha256) = 32)
    AND (d.fits_index_storage_key IS NULL OR octet_length(d.fits_index_storage_key) <= 1024)
    AND (d.fits_index_version_id IS NULL OR octet_length(d.fits_index_version_id) <= 1024)
    AND (d.fits_index_sha256 IS NULL OR octet_length(d.fits_index_sha256) = 32)
    AND (d.final_pdf_key IS NULL OR octet_length(d.final_pdf_key) <= 1024)
    AND (d.final_pdf_version_id IS NULL OR octet_length(d.final_pdf_version_id) <= 1024)
    AND (d.final_pdf_sha IS NULL OR octet_length(d.final_pdf_sha) = 32)
    AND (d.audit_cert_key IS NULL OR octet_length(d.audit_cert_key) <= 1024)
    AND (d.audit_cert_version_id IS NULL OR octet_length(d.audit_cert_version_id) <= 1024)
    AND (d.audit_cert_sha256 IS NULL OR octet_length(d.audit_cert_sha256) = 32)
    AND (d.audit_payload_key IS NULL OR octet_length(d.audit_payload_key) <= 1024)
    AND (d.audit_payload_version_id IS NULL OR octet_length(d.audit_payload_version_id) <= 1024)
    AND (d.audit_payload_sha256 IS NULL OR octet_length(d.audit_payload_sha256) = 32)
    AND (d.audit_signature_key IS NULL OR octet_length(d.audit_signature_key) <= 1024)
    AND (d.audit_signature_version_id IS NULL OR octet_length(d.audit_signature_version_id) <= 1024)
    AND (d.audit_signature_sha256 IS NULL OR octet_length(d.audit_signature_sha256) = 32)
FOR UPDATE OF d;

-- name: ListFittedFinalizationRecoverySignatureMetadata :many
-- Keep every row, including malformed rows, so invalid metadata cannot be
-- hidden by a filter and turn a partial set into apparent success. LIMIT101
-- includes a refusal sentinel above the maximum100 parties. CASE expressions
-- prevent copying an oversized legacy key/version/digest/kind to the client.
SELECT s.id, s.document_id, s.recipient_id, s.field_id, s.signed_at,
    CASE WHEN octet_length(s.signature_kind) <= 32 THEN s.signature_kind ELSE '' END::text AS signature_kind,
    CASE WHEN octet_length(s.image_storage_key) <= 1024 THEN s.image_storage_key ELSE '' END::text AS image_storage_key,
    CASE WHEN octet_length(s.image_version_id) <= 1024 THEN s.image_version_id ELSE '' END::text AS image_version_id,
    CASE WHEN octet_length(s.image_sha256) = 32 THEN s.image_sha256 ELSE NULL END::bytea AS image_sha256,
    s.image_version_pin_required, s.presign_execution_id,
    COALESCE(octet_length(s.signature_kind) BETWEEN 1 AND 32
        AND octet_length(s.image_storage_key) BETWEEN 1 AND 1024
        AND octet_length(s.image_version_id) BETWEEN 1 AND 1024
        AND octet_length(s.image_sha256) = 32, FALSE)::boolean AS metadata_valid
FROM signatures s JOIN documents d ON d.id = s.document_id
WHERE s.document_id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
ORDER BY s.signed_at, s.id
LIMIT 101;

-- name: ListFittedFinalizationRecoveryCompanions :many
-- Match the signature projection's refusal sentinel before adapter maps/copies.
SELECT c.* FROM signature_fit_companions c JOIN signatures s ON s.id = c.signature_id
WHERE c.document_id = sqlc.arg(document_id) AND c.org_id = sqlc.arg(org_id)
ORDER BY s.signed_at, s.id
LIMIT 101;
