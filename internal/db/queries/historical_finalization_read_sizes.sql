-- Fixed native historical finalization projections. Scalar metadata precedes
-- every expandable signature/intent row; actual root/session locks, a fresh
-- post-pin scalar recheck and exact body byte comparison remain mandatory.

-- name: GetHistoricalFinalizationSignatureReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d
)
SELECT d.id AS document_id,d.org_id,d.updated_at,
 count(s.id)::bigint AS signature_count,
 COALESCE(sum(COALESCE(octet_length(s.font),0)::numeric
 +COALESCE(octet_length(s.typed_name),0)+COALESCE(octet_length(s.image_storage_key),0)
 +COALESCE(octet_length(s.image_sha256),0)+COALESCE(octet_length(s.image_version_id),0)
 +COALESCE(octet_length(s.signer_ua),0)+COALESCE(octet_length(s.signature_kind),0)),0)::bigint AS raw_bytes
FROM parent d LEFT JOIN signatures s ON s.document_id=d.id
GROUP BY d.id,d.org_id,d.updated_at;

-- name: LockHistoricalFinalizationSignatureRowsV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d
), pinned AS MATERIALIZED (
 SELECT s.id FROM signatures s JOIN parent d ON d.id=s.document_id
 ORDER BY s.id FOR SHARE OF s
)
SELECT count(*)::bigint AS signature_count FROM pinned;

-- name: GetHistoricalFinalizationIntentReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d
), intent AS MATERIALIZED (
 SELECT i.document_id,i.org_id,
 (COALESCE(octet_length(i.mode),0)::numeric
 +COALESCE(octet_length(i.final_pdf_key),0)+COALESCE(octet_length(i.final_pdf_sha256),0)
 +COALESCE(octet_length(i.final_pdf_version_id),0)+COALESCE(octet_length(i.audit_cert_key),0)
 +COALESCE(octet_length(i.audit_cert_sha256),0)+COALESCE(octet_length(i.audit_cert_version_id),0)
 +COALESCE(octet_length(i.audit_payload_key),0)+COALESCE(octet_length(i.audit_payload_sha256),0)
 +COALESCE(octet_length(i.audit_payload_version_id),0)+COALESCE(octet_length(i.audit_signature_key),0)
 +COALESCE(octet_length(i.audit_signature_sha256),0)+COALESCE(octet_length(i.audit_signature_version_id),0)
 +COALESCE(octet_length(i.last_error),0)+COALESCE(octet_length(i.fits_index_storage_key),0)
 +COALESCE(octet_length(i.fits_index_version_id),0)+COALESCE(octet_length(i.fits_index_sha256),0))::bigint AS raw_bytes
 FROM document_finalization_intents i JOIN parent d ON d.id=i.document_id AND d.org_id=i.org_id
 FOR UPDATE OF i
)
SELECT d.id AS document_id,d.org_id,d.updated_at,
 (i.document_id IS NOT NULL)::boolean AS has_intent,
 COALESCE(i.raw_bytes,0)::bigint AS raw_bytes
FROM parent d LEFT JOIN intent i ON i.document_id=d.id AND i.org_id=d.org_id;
