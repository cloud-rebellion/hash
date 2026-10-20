-- Native fresh plain-PDF creation only. Identity is allocated privately before
-- this INSERT; original author/quota/template/credential checks remain in the
-- fixed producer. An existing row can never be adopted by this statement.
-- name: CreateFreshPlainPDFDocumentV1 :one
INSERT INTO documents (id,org_id,template_id,name,source_kind,variables_json,
 pdf_storage_key,pdf_sha256,pdf_storage_version_id,evidence_version_pins_required,sender_id,expires_at)
VALUES (sqlc.arg(id),sqlc.arg(org_id),sqlc.arg(template_id),sqlc.arg(name),
 'pdf','{}'::jsonb,sqlc.arg(pdf_storage_key),sqlc.arg(pdf_sha256),sqlc.arg(pdf_storage_version_id),
 sqlc.arg(evidence_version_pins_required),sqlc.arg(sender_id),sqlc.arg(expires_at))
RETURNING *;

-- name: MeasurePlainPDFCreationResponseV1 :one
-- Only the same native fresh INSERT owner, under its exact input/report loan.
-- The producer proves NULL blocks/literal {} metadata from its own new row;
-- old cache absence, a UUID or a caller-supplied document is not authority.
-- Intrinsic M92 guard derives both actual values, discarding placeholders.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
  AND d.deleted_at IS NULL AND d.status='draft' AND d.source_kind='pdf'
  AND d.html_source_json IS NULL AND d.html_current_source_json IS NULL
  AND d.blocks_json IS NULL
 FOR UPDATE OF d NOWAIT
)
INSERT INTO html_creation_response_sizes_v1(document_id,org_id,blocks_wire_bytes,metadata_wire_bytes,measurement_server_version_num,measured_at)
SELECT d.id,d.org_id,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent d
ON CONFLICT(document_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;

-- name: GetPlainFieldRecipientReadHeaderV1 :one
-- Original document parent is already held FOR UPDATE by the actual field
-- mutation reader. Only scalar TEXT/BYTEA lengths precede the complete row.
SELECT r.id,r.document_id,
 (octet_length(r.role)::numeric+octet_length(r.email)+octet_length(r.name)+octet_length(r.status)
  +COALESCE(octet_length(r.declined_reason),0)+octet_length(r.locale)+COALESCE(octet_length(r.magic_token_hash),0))::bigint AS raw_text_bytes
FROM recipients r JOIN documents d ON d.id=r.document_id
WHERE r.id=sqlc.arg(recipient_id)::uuid AND d.id=sqlc.arg(document_id)::uuid
 AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
FOR SHARE OF r;

-- name: ReadPlainFieldRecipientV1 :one
SELECT r.* FROM recipients r JOIN documents d ON d.id=r.document_id
WHERE r.id=sqlc.arg(recipient_id)::uuid AND d.id=sqlc.arg(document_id)::uuid
 AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND (octet_length(r.role)::numeric+octet_length(r.email)+octet_length(r.name)+octet_length(r.status)
  +COALESCE(octet_length(r.declined_reason),0)+octet_length(r.locale)+COALESCE(octet_length(r.magic_token_hash),0))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;
