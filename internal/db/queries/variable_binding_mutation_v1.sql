-- Fixed native binding producer. Root discovery is scalar and grants no write
-- authority. The genuine producer locks that root before the target reader.
-- name: GetVariableBindingMutationRootV1 :one
SELECT r.id AS root_document_id
FROM documents d JOIN documents r ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid
 AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL;

-- name: LockVariableBindingMutationRootV1 :one
SELECT r.id AS root_document_id,
 CASE WHEN octet_length(r.status)=5 THEN r.status='draft' ELSE false END AS is_draft
FROM documents r WHERE r.id=sqlc.arg(root_document_id)::uuid
 AND r.org_id=sqlc.arg(org_id)::uuid AND r.deleted_at IS NULL
 AND r.parent_envelope_id IS NULL
 AND EXISTS(SELECT 1 FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid
  AND d.org_id=r.org_id AND d.deleted_at IS NULL
  AND COALESCE(d.parent_envelope_id,d.id)=r.id)
FOR UPDATE OF r;

-- Fresh READ COMMITTED statement after the possible root wait. The actual
-- target is separately locked/read by the genuine revision reader afterwards.
-- name: VariableBindingMutationRootMatchesV1 :one
SELECT EXISTS(SELECT 1 FROM documents d JOIN documents r
 ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND r.id=sqlc.arg(root_document_id)::uuid
 AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL
 AND CASE WHEN octet_length(r.status)=5 THEN r.status='draft' ELSE false END
 AND (d.id=r.id OR (r.is_envelope AND NOT d.is_envelope)));

-- The target and physical family root are already owned. Lock only the one
-- existing definition. No old source/ref/fallback/observation text is expanded.
-- name: GetVariableBindingMutationHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid
 AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND CASE WHEN octet_length(d.status)=5 THEN d.status='draft' ELSE false END
 FOR UPDATE OF d
), binding AS MATERIALIZED (
 SELECT b.document_id,b.created_at,b.updated_at,b.last_resolved,
 (octet_length(b.variable_name)::numeric+octet_length(b.source_kind)::numeric
 +octet_length(b.source_ref)::numeric+octet_length(b.source_path)::numeric
 +octet_length(b.fallback)::numeric+octet_length(b.last_value)::numeric
 +octet_length(b.last_error)::numeric)::bigint AS raw_text_bytes
 FROM document_variable_bindings b JOIN parent p ON p.id=b.document_id
 WHERE b.variable_name=sqlc.arg(variable_name)::text FOR UPDATE OF b
)
SELECT (b.document_id IS NOT NULL)::boolean AS present,b.created_at,b.updated_at,b.last_resolved,
 COALESCE(b.raw_text_bytes,0)::bigint AS raw_text_bytes
FROM parent p LEFT JOIN binding b ON b.document_id=p.id;

-- name: ReadVariableBindingMutationSourceV1 :one
SELECT b.* FROM document_variable_bindings b JOIN documents d ON d.id=b.document_id
WHERE b.document_id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND d.status='draft' AND b.variable_name=sqlc.arg(variable_name)::text
 AND b.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND b.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (octet_length(b.variable_name)::numeric+octet_length(b.source_kind)::numeric
 +octet_length(b.source_ref)::numeric+octet_length(b.source_path)::numeric
 +octet_length(b.fallback)::numeric+octet_length(b.last_value)::numeric
 +octet_length(b.last_error)::numeric)::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;
