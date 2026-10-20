-- Exact fit inventory is a recovery protocol, not caller authorization. The
-- signing service must rebind source/all targets/notice/original credential
-- under document -> recipient locks before selecting and before final Sign.
-- No cleanup query may infer absence from an unknown upload or SQL commit.

-- name: ReserveSignatureFitPreparation :one
WITH locked_document AS MATERIALIZED (
 SELECT doc.id,doc.org_id FROM documents doc WHERE doc.id=sqlc.arg(document_id) AND doc.org_id=sqlc.arg(org_id)
 AND doc.deleted_at IS NULL FOR UPDATE OF doc
), locked_recipient AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN locked_document d ON d.id=r.document_id
 WHERE r.id=sqlc.arg(recipient_id) FOR UPDATE OF r
)
INSERT INTO signature_fit_preparations (
 id,org_id,document_id,recipient_id,ceremony_epoch,authority_sha256,
 source_storage_key,source_version_id,source_sha256,source_bytes,
 geometry_sha256,span_sha256,reserved_bytes,expected_objects,owner_id,lease_until
)
SELECT sqlc.arg(id),sqlc.arg(org_id),sqlc.arg(document_id),r.id,sqlc.arg(ceremony_epoch),sqlc.arg(authority_sha256),
 sqlc.arg(source_storage_key),sqlc.arg(source_version_id),sqlc.arg(source_sha256),sqlc.arg(source_bytes),
 sqlc.arg(geometry_sha256),sqlc.arg(span_sha256),sqlc.arg(reserved_bytes),sqlc.arg(expected_objects),sqlc.arg(owner_id),sqlc.arg(lease_until)
FROM locked_recipient r RETURNING *;

-- name: GetSignatureFitPreparation :one
SELECT * FROM signature_fit_preparations WHERE id=$1 AND org_id=$2;

-- name: GetSignatureFitPreparationForUpdate :one
-- Caller already holds its document -> recipient locks.
SELECT * FROM signature_fit_preparations WHERE id=$1 AND org_id=$2 FOR UPDATE;

-- name: ClaimSignatureFitPreparationLease :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
)
UPDATE signature_fit_preparations p SET owner_id=sqlc.arg(owner_id),lease_until=sqlc.arg(lease_until),
 attempts=p.attempts+1,updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.status<>'cleaned' AND p.lease_until<=clock_timestamp() AND p.attempts<8
 AND sqlc.arg(lease_until)::timestamptz>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=p.id)
RETURNING p.*;

-- name: ReserveSignatureFitObject :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.owner_id=sqlc.arg(owner_id)
 AND p.status='staging' AND p.lease_until>clock_timestamp() FOR UPDATE OF p
)
INSERT INTO signature_fit_objects(preparation_id,kind,page,storage_key,sha256,bytes,content_type)
SELECT o.id,sqlc.arg(kind),sqlc.arg(page),sqlc.arg(storage_key),sqlc.arg(sha256),sqlc.arg(bytes),sqlc.arg(content_type)
FROM operation o RETURNING *;

-- name: ListSignatureFitObjects :many
SELECT o.* FROM signature_fit_objects o JOIN signature_fit_preparations p ON p.id=o.preparation_id
WHERE p.id=$1 AND p.org_id=$2 ORDER BY CASE o.kind WHEN 'span' THEN 0 WHEN 'page' THEN 1 ELSE 2 END,o.page;

-- name: MarkSignatureFitUploadAttempted :one
-- Commit this monotone inventory checkpoint BEFORE the sole Put request. It
-- records the original uploader even if a later recovery claims the lease.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.owner_id=sqlc.arg(owner_id)
 AND p.status='staging' AND p.lease_until>clock_timestamp() FOR UPDATE OF p
)
UPDATE signature_fit_objects o SET upload_attempted_at=clock_timestamp(),upload_owner_id=p.owner_id
FROM operation p WHERE o.preparation_id=p.id AND o.kind=sqlc.arg(kind) AND o.page=sqlc.arg(page)
 AND o.upload_attempted_at IS NULL AND o.version_id IS NULL RETURNING o.*;

-- name: PinSignatureFitObjectVersion :one
-- A positive exact version may reconcile an uncertain original Put. This
-- never authorizes overwriting/retrying Put or interpreting empty history as
-- safe cleanup. Root verifies key/size/digest/MIME before invoking this query.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.owner_id=sqlc.arg(owner_id)
 AND p.status IN('staging','abandoned') AND p.lease_until>clock_timestamp() FOR UPDATE OF p
)
UPDATE signature_fit_objects o SET version_id=COALESCE(o.version_id,sqlc.arg(version_id)::text)
FROM operation p WHERE o.preparation_id=p.id AND o.kind=sqlc.arg(kind) AND o.page=sqlc.arg(page)
 AND o.upload_attempted_at IS NOT NULL AND o.cleanup_completed_at IS NULL
 AND (o.version_id IS NULL OR o.version_id=sqlc.arg(version_id)::text) RETURNING o.*;

-- name: MarkSignatureFitObjectReadbackVerified :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.owner_id=sqlc.arg(owner_id)
 AND p.status IN('staging','abandoned') AND p.lease_until>clock_timestamp() FOR UPDATE OF p
)
UPDATE signature_fit_objects o SET readback_verified_at=COALESCE(o.readback_verified_at,GREATEST(clock_timestamp(),o.upload_attempted_at))
FROM operation p WHERE o.preparation_id=p.id AND o.kind=sqlc.arg(kind) AND o.page=sqlc.arg(page)
 AND o.version_id=sqlc.arg(version_id)::text AND o.sha256=sqlc.arg(sha256) AND o.bytes=sqlc.arg(bytes)
 AND o.cleanup_completed_at IS NULL RETURNING o.*;

-- name: MarkSignatureFitPreparationPrepared :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
)
UPDATE signature_fit_preparations p SET status='prepared',updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status='staging' RETURNING p.*;

-- name: MarkSignatureFitSelectionCommitAttempted :one
-- Persist BEFORE entering the selection transaction. Unknown COMMIT remains
-- protected until the exact ceremony selection is read back/reconciled.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
)
UPDATE signature_fit_preparations p SET selection_commit_attempted_at=COALESCE(p.selection_commit_attempted_at,clock_timestamp()),updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status='prepared'
 AND p.selection_not_committed_at IS NULL AND NOT EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=p.id)
RETURNING p.*;

-- name: SelectSignatureFitPreparation :one
-- Execute inside the original credential/source/ALL-target admission
-- transaction. One stable exact set is selected; conflicts are reconciled by
-- GetSignatureFitSelection, never by replacing bytes or choosing a retry PDF.
WITH parent AS MATERIALIZED (
 SELECT doc.id,doc.org_id FROM documents doc WHERE doc.id=sqlc.arg(document_id) AND doc.org_id=sqlc.arg(org_id)
 AND doc.deleted_at IS NULL AND doc.status IN('sent','in_progress')
 AND doc.article13_notice_epoch_at=sqlc.arg(ceremony_epoch) AND doc.article13_notice_epoch_v61_committed FOR UPDATE OF doc
), recipient AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id
 WHERE r.id=sqlc.arg(recipient_id) AND r.status IN('pending','sent','viewed') FOR UPDATE OF r
), operation AS MATERIALIZED (
 SELECT p.* FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id AND d.org_id=p.org_id
 JOIN recipient r ON r.id=p.recipient_id WHERE p.id=sqlc.arg(preparation_id)
 AND p.ceremony_epoch=sqlc.arg(ceremony_epoch) AND p.authority_sha256=sqlc.arg(authority_sha256)
 AND p.status='prepared' AND p.selection_commit_attempted_at IS NOT NULL AND p.selection_not_committed_at IS NULL FOR UPDATE OF p
)
INSERT INTO signature_fit_selections (
 id,preparation_id,org_id,document_id,recipient_id,ceremony_epoch,authority_sha256,
 source_storage_key,source_version_id,source_sha256,source_bytes,geometry_sha256,
 span_storage_key,span_version_id,span_sha256,span_bytes,
 manifest_storage_key,manifest_version_id,manifest_sha256,manifest_bytes,retain_until
)
SELECT sqlc.arg(id),p.id,p.org_id,p.document_id,p.recipient_id,p.ceremony_epoch,p.authority_sha256,
 p.source_storage_key,p.source_version_id,p.source_sha256,p.source_bytes,p.geometry_sha256,
 sp.storage_key,sp.version_id,sp.sha256,sp.bytes,mf.storage_key,mf.version_id,mf.sha256,mf.bytes,
 hash_evidence_retain_until(p.ceremony_epoch,7)
FROM operation p JOIN signature_fit_objects sp ON sp.preparation_id=p.id AND sp.kind='span' AND sp.page=0
JOIN signature_fit_objects mf ON mf.preparation_id=p.id AND mf.kind='manifest' AND mf.page=0 RETURNING *;

-- name: GetSignatureFitSelection :one
SELECT * FROM signature_fit_selections WHERE document_id=$1 AND recipient_id=$2 AND ceremony_epoch=$3 AND org_id=$4;

-- name: GetSignatureFitSelectionForUpdate :one
-- Caller already holds document -> recipient locks.
SELECT * FROM signature_fit_selections WHERE document_id=$1 AND recipient_id=$2 AND ceremony_epoch=$3 AND org_id=$4 FOR UPDATE;

-- name: MarkSignatureFitSelectionNotCommitted :one
-- The parent lock prevents a later selection racing this negative SQL
-- reconciliation. The checkpoint permanently closes this operation for select.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
)
UPDATE signature_fit_preparations p SET selection_not_committed_at=COALESCE(p.selection_not_committed_at,GREATEST(clock_timestamp(),p.selection_commit_attempted_at)),updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status='prepared'
 AND p.selection_commit_attempted_at IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=p.id)
RETURNING p.*;

-- name: MarkSignatureFitRetentionStarted :one
UPDATE signature_fit_selections SET retention_started_at=COALESCE(retention_started_at,clock_timestamp())
WHERE id=$1 AND org_id=$2 RETURNING *;

-- name: MarkSignatureFitRetentionComplete :one
-- Invoke only after retention and independent exact-version readback of ALL
-- selected span/page/manifest objects to this precommitted whole-second target.
UPDATE signature_fit_selections SET retention_completed_at=COALESCE(retention_completed_at,GREATEST(clock_timestamp(),retention_started_at))
WHERE id=$1 AND org_id=$2 AND retention_started_at IS NOT NULL RETURNING *;

-- name: CreateSignatureFitCompanion :one
-- Insert atomically with the new fitted signature. Deferred pairing requires
-- the exact retained selection and original span image pin; legacy signatures
-- and the delegated execution pairing from migration82 remain separate.
INSERT INTO signature_fit_companions(signature_id,org_id,document_id,recipient_id,field_id,selection_id,span_sha256)
VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *;

-- name: GetSignatureFitCompanion :one
SELECT * FROM signature_fit_companions WHERE signature_id=$1 AND org_id=$2;

-- name: ListDocumentSignatureFitCompanions :many
SELECT c.* FROM signature_fit_companions c JOIN signatures s ON s.id=c.signature_id
WHERE c.document_id=$1 AND c.org_id=$2 ORDER BY s.signed_at,s.id;

-- name: AbandonSignatureFitPreparation :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
)
UPDATE signature_fit_preparations p SET status='abandoned',updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status IN('staging','prepared')
 AND (p.selection_commit_attempted_at IS NULL OR p.selection_not_committed_at IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=p.id) RETURNING p.*;

-- name: BeginSignatureFitCleanup :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
)
UPDATE signature_fit_preparations p SET status='cleaning',updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status='abandoned'
 AND NOT EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=p.id)
 AND NOT EXISTS(SELECT 1 FROM signature_fit_objects o WHERE o.preparation_id=p.id AND o.upload_attempted_at IS NOT NULL AND o.version_id IS NULL)
RETURNING p.*;

-- name: MarkSignatureFitObjectCleanupComplete :one
-- Root must establish terminal ownership and delete/readback the exact pinned
-- version (or prove this reserved object was never attempted). NULL-version
-- attempted rows cannot reach this checkpoint.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id FROM signature_fit_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.owner_id=sqlc.arg(owner_id)
 AND p.status='cleaning' AND p.lease_until>clock_timestamp() FOR UPDATE OF p
)
UPDATE signature_fit_objects o SET cleanup_completed_at=COALESCE(o.cleanup_completed_at,clock_timestamp())
FROM operation p WHERE o.preparation_id=p.id AND o.kind=sqlc.arg(kind) AND o.page=sqlc.arg(page)
 AND (o.upload_attempted_at IS NULL OR o.version_id IS NOT NULL) RETURNING o.*;

-- name: CompleteSignatureFitCleanup :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN signature_fit_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) FOR UPDATE OF d
)
UPDATE signature_fit_preparations p SET status='cleaned',updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status='cleaning'
 AND NOT EXISTS(SELECT 1 FROM signature_fit_objects o WHERE o.preparation_id=p.id AND o.cleanup_completed_at IS NULL)
RETURNING p.*;

-- name: ListSignatureFitRecoveryPreparations :many
SELECT p.* FROM signature_fit_preparations p WHERE p.status<>'cleaned'
 AND NOT EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=p.id)
ORDER BY p.lease_until,p.id LIMIT $1;

-- name: ListSignatureFitPendingRetention :many
SELECT * FROM signature_fit_selections WHERE retention_completed_at IS NULL ORDER BY created_at,id LIMIT $1;

-- name: ListSignatureFitInventory :many
-- Includes uncertain uploads/commit attempts and cleaned inventory. Consumer
-- privacy/recovery code must enumerate it rather than only final signatures.
-- The8193rd row is an overflow sentinel; production adapters refuse it rather
-- than returning partial inventory or allocating an unbounded row collection.
SELECT p.id AS preparation_id,p.recipient_id,p.ceremony_epoch,p.status,p.owner_id,p.lease_until,
 p.expected_objects,p.reserved_bytes,
 p.selection_commit_attempted_at,p.selection_not_committed_at,
 o.kind,o.page,o.storage_key,o.sha256,o.bytes,o.content_type,o.upload_attempted_at,o.upload_owner_id,
 o.version_id,o.readback_verified_at,o.cleanup_completed_at,s.id AS selection_id,s.retain_until,s.retention_started_at,s.retention_completed_at
FROM signature_fit_preparations p LEFT JOIN signature_fit_objects o ON o.preparation_id=p.id
LEFT JOIN signature_fit_selections s ON s.preparation_id=p.id
WHERE p.document_id=$1 AND p.org_id=$2 ORDER BY p.id,o.kind,o.page LIMIT 8193;
