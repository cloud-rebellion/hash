-- Opt-in original capture/read APIs. Callers own global DB staging/resource
-- admission and validate canonical authority/package bytes before copying or
-- dispatch. Metadata never includes original bodies; body reads require exact
-- metadata SHA/size and caller admission. Read-only identity reuse is supported
-- by Get methods, never INSERT ON CONFLICT or an UPDATE of originals.
-- Unknown SQL commit/physical session outcomes require fresh reconciliation;
-- absence here is not upload/re-render/delete permission.

-- name: GetSignatureFitOriginalOperationForUpdate :one
-- READ COMMITTED document -> recipient -> operation. Project locked tuples
-- inside MATERIALIZED CTEs, not a stale rejoin after waiting. The outer server
-- clock evaluates lease only after all locks. Hold this actual transaction
-- through the guarded capture/reservation, never use a pool-backed facade.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.source_kind AS document_type,d.status AS document_status,
  (d.deleted_at IS NOT NULL)::boolean AS document_deleted,d.article13_notice_epoch_v61_committed AS notice_committed,
  d.sent_at,d.article13_notice_epoch_at,d.pdf_storage_key,d.pdf_storage_version_id,d.pdf_sha256,
  d.requires_signature,d.evidence_version_pins_required,d.is_envelope,d.parent_envelope_id
 FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), recipient AS MATERIALIZED (
 SELECT r.id,r.document_id,r.status AS recipient_status,r.role AS recipient_role
 FROM recipients r JOIN parent d ON d.id=r.document_id
 JOIN signature_fit_preparations p ON p.id=sqlc.arg(preparation_id) AND p.org_id=d.org_id AND p.document_id=d.id AND p.recipient_id=r.id
 FOR UPDATE OF r
), operation AS MATERIALIZED (
 SELECT p.id,p.org_id,p.document_id,p.recipient_id,p.ceremony_epoch,p.authority_sha256,
  p.source_storage_key,p.source_version_id,p.source_sha256,p.source_bytes,p.geometry_sha256,p.span_sha256,
  p.reserved_bytes,p.expected_objects,p.owner_id,p.lease_until,p.attempts,p.status,
  p.selection_commit_attempted_at,p.selection_not_committed_at,p.created_at,p.updated_at,
  d.document_type,d.document_status,d.document_deleted,d.notice_committed,
  d.requires_signature,d.evidence_version_pins_required,d.is_envelope,d.parent_envelope_id,
  r.recipient_status,r.recipient_role,
  COALESCE(d.sent_at=p.ceremony_epoch AND d.article13_notice_epoch_at=p.ceremony_epoch,FALSE)::boolean AS notice_current,
  ROW(d.pdf_storage_key,d.pdf_storage_version_id,d.pdf_sha256)
   IS NOT DISTINCT FROM ROW(p.source_storage_key,p.source_version_id,p.source_sha256) AS source_current
 FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id AND d.org_id=p.org_id
 JOIN recipient r ON r.id=p.recipient_id AND r.document_id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
  AND p.owner_id=sqlc.arg(owner_id) FOR UPDATE OF p
)
SELECT operation.*,operation.lease_until>clock_timestamp() AS lease_current FROM operation;

-- name: CaptureSignatureFitOriginalAuthority :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), recipient AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id
 WHERE r.id=sqlc.arg(recipient_id) FOR UPDATE OF r
), operation AS MATERIALIZED (
 SELECT p.id,p.org_id,p.document_id,p.recipient_id,p.ceremony_epoch,p.owner_id,p.lease_until,p.status,p.selection_commit_attempted_at
 FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id AND d.org_id=p.org_id JOIN recipient r ON r.id=p.recipient_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
  AND p.owner_id=sqlc.arg(owner_id) FOR UPDATE OF p
)
INSERT INTO signature_fit_original_authorities AS original(preparation_id,org_id,document_id,recipient_id,ceremony_epoch,
 authority_payload,authority_sha256,authority_bytes,occupied_pages,captured_owner_id)
SELECT p.id,p.org_id,p.document_id,p.recipient_id,sqlc.arg(ceremony_epoch),sqlc.arg(authority_payload),
 sqlc.arg(authority_sha256),sqlc.arg(authority_bytes),sqlc.arg(occupied_pages),p.owner_id
FROM operation p WHERE p.status='staging' AND p.selection_commit_attempted_at IS NULL AND p.lease_until>clock_timestamp()
RETURNING original.preparation_id,original.org_id,original.document_id,original.recipient_id,original.ceremony_epoch,
 original.authority_sha256,original.authority_bytes,original.occupied_pages,original.captured_owner_id,original.captured_at;

-- name: CaptureSignatureFitOriginalPayload :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), recipient AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id
 JOIN signature_fit_preparations p ON p.id=sqlc.arg(preparation_id) AND p.org_id=d.org_id AND p.document_id=d.id AND p.recipient_id=r.id
 FOR UPDATE OF r
), operation AS MATERIALIZED (
 SELECT p.id,p.org_id,p.document_id,p.owner_id,p.lease_until,p.status,p.selection_commit_attempted_at
 FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id AND d.org_id=p.org_id JOIN recipient r ON r.id=p.recipient_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
  AND p.owner_id=sqlc.arg(owner_id) FOR UPDATE OF p
)
INSERT INTO signature_fit_original_payloads AS original(preparation_id,org_id,document_id,kind,page,
 storage_key,sha256,bytes,content_type,payload,captured_owner_id)
SELECT p.id,p.org_id,p.document_id,sqlc.arg(kind),sqlc.arg(page),sqlc.arg(storage_key),
 sqlc.arg(sha256),sqlc.arg(bytes),sqlc.arg(content_type),sqlc.arg(payload),p.owner_id
FROM operation p WHERE p.status='staging' AND p.selection_commit_attempted_at IS NULL AND p.lease_until>clock_timestamp()
RETURNING original.preparation_id,original.org_id,original.document_id,original.kind,original.page,
 original.storage_key,original.sha256,original.bytes,original.content_type,original.captured_owner_id,original.captured_at;

-- name: GetSignatureFitOriginalAuthorityMetadata :one
SELECT original.preparation_id,original.org_id,original.document_id,original.recipient_id,original.ceremony_epoch,
 original.authority_sha256,original.authority_bytes,original.occupied_pages,original.captured_owner_id,original.captured_at
FROM signature_fit_original_authorities original
WHERE original.preparation_id=sqlc.arg(preparation_id) AND original.org_id=sqlc.arg(org_id) AND original.document_id=sqlc.arg(document_id);

-- name: GetSignatureFitOriginalAuthorityBody :one
-- Must follow admitted exact scoped metadata; immutable original bytes only.
SELECT original.authority_payload FROM signature_fit_original_authorities original
WHERE original.preparation_id=sqlc.arg(preparation_id) AND original.org_id=sqlc.arg(org_id) AND original.document_id=sqlc.arg(document_id)
 AND original.authority_sha256=sqlc.arg(expected_sha256) AND original.authority_bytes=sqlc.arg(expected_bytes)
 AND sqlc.arg(expected_bytes)::bigint BETWEEN 1 AND 1048576;

-- name: GetSignatureFitOriginalPayloadMetadata :one
SELECT original.preparation_id,original.org_id,original.document_id,original.kind,original.page,
 original.storage_key,original.sha256,original.bytes,original.content_type,original.captured_owner_id,original.captured_at
FROM signature_fit_original_payloads original
WHERE original.preparation_id=sqlc.arg(preparation_id) AND original.org_id=sqlc.arg(org_id) AND original.document_id=sqlc.arg(document_id)
 AND original.kind=sqlc.arg(kind) AND original.page=sqlc.arg(page);

-- name: GetSignatureFitOriginalPayloadBody :one
-- Never returns a freshly rendered replacement. All capacities must be
-- reserved before this bytea is retrieved; exact SHA/size follows metadata.
SELECT original.payload FROM signature_fit_original_payloads original
WHERE original.preparation_id=sqlc.arg(preparation_id) AND original.org_id=sqlc.arg(org_id) AND original.document_id=sqlc.arg(document_id)
 AND original.kind=sqlc.arg(kind) AND original.page=sqlc.arg(page)
 AND original.sha256=sqlc.arg(expected_sha256) AND original.bytes=sqlc.arg(expected_bytes)
 AND sqlc.arg(expected_bytes)::bigint BETWEEN 1 AND 16777276;

-- name: ListSignatureFitOriginalPayloadMetadata :many
-- Fixed sentinel limit: caller rejects 503, never treats a truncated inventory
-- as a complete set. Header exists before any member and each member is unique.
SELECT original.preparation_id,original.org_id,original.document_id,original.kind,original.page,
 original.storage_key,original.sha256,original.bytes,original.content_type,original.captured_owner_id,original.captured_at
FROM signature_fit_original_payloads original
WHERE original.preparation_id=sqlc.arg(preparation_id) AND original.org_id=sqlc.arg(org_id) AND original.document_id=sqlc.arg(document_id)
ORDER BY CASE original.kind WHEN 'span' THEN 0 WHEN 'page' THEN 1 ELSE 2 END,original.page LIMIT 503;

-- name: ListSignatureFitOriginalPrivacyInventory :many
-- Includes retained originals even after85 cleanup, completed selection or an
-- unknown upload/commit. No body/name/font is returned and no erasure mutation
-- or hold exception is invented. At most128 preparations per document.
SELECT a.preparation_id,a.org_id,a.document_id,a.recipient_id,a.ceremony_epoch,a.authority_sha256,a.authority_bytes,
 a.captured_at,p.status,p.selection_commit_attempted_at,p.selection_not_committed_at,
 count(body.preparation_id)::bigint AS payload_count,COALESCE(sum(body.bytes),0)::bigint AS payload_bytes
FROM signature_fit_original_authorities a JOIN signature_fit_preparations p ON p.id=a.preparation_id
LEFT JOIN signature_fit_original_payloads body ON body.preparation_id=a.preparation_id
WHERE a.org_id=sqlc.arg(org_id) AND a.document_id=sqlc.arg(document_id)
GROUP BY a.preparation_id,a.org_id,a.document_id,a.recipient_id,a.ceremony_epoch,a.authority_sha256,a.authority_bytes,
 a.captured_at,p.status,p.selection_commit_attempted_at,p.selection_not_committed_at
ORDER BY a.preparation_id LIMIT 129;
