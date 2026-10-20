-- The guarded86 journal is authoritative only with real application capture,
-- locked Sign admission and trusted signed-index/package verification. Every
-- mutation is tenant/document/operation/current-owner scoped and locks the
-- document before the operation. Commit checkpoints before external IO. An
-- attempted upload is never replay permission, including an empty listing.
-- No body discard, row deletion, provider compensation or cleanup inference is
-- exposed: durable controller/hold disposition and physical SQL/provider
-- uncertainty reconciliation remain separate application requirements.

-- name: RequireDocumentFitsIndex :execrows
-- Set inside the FIRST actual fitted Sign transaction, never during fitting or
-- selection. Deferred86 pairing requires the genuine fitted signature and85
-- companion in that same atomic transaction. The caller already holds root,
-- recipient and credential authority locks and has completed full admission.
UPDATE documents SET fits_index_required=TRUE,updated_at=clock_timestamp()
WHERE id=sqlc.arg(document_id) AND org_id=sqlc.arg(org_id)
 AND status IN('sent','in_progress') AND source_kind='pdf' AND requires_signature
 AND NOT is_envelope AND parent_envelope_id IS NULL AND deleted_at IS NULL
 AND article13_notice_epoch_v61_committed AND article13_notice_epoch_at=sqlc.arg(ceremony_epoch)
 AND NOT fits_index_required;

-- name: CaptureFittedFinalizationPreparation :one
-- Freeze exact canonical field/legacy and all-page geometry bytes while real
-- document/recipient/source authority is locked. The trigger binds them to all
-- actual fields/signatures/85 companion selections. Limits must already have
-- passed the prospective pre-Sign producer/processing/full-archive gate.
WITH parent AS MATERIALIZED (
 SELECT d.* FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND d.status='finalizing' AND d.fits_index_required AND d.deleted_at IS NULL FOR UPDATE OF d
), chosen AS MATERIALIZED (
 SELECT x.* FROM signature_fit_companions c JOIN signature_fit_selections x ON x.id=c.selection_id
 JOIN parent d ON c.org_id=d.org_id AND c.document_id=d.id ORDER BY c.signature_id LIMIT 1
)
INSERT INTO document_finalization_preparations AS preparation(
 id,org_id,document_id,ceremony_epoch,completion_effective_at,retain_until,original_document_name,
 source_storage_key,source_version_id,source_sha256,source_bytes,source_pages,
 geometry_pages_payload,geometry_sha256,field_snapshot_payload,field_snapshot_sha256,
 required_base_pages,expected_outputs,expected_references,fit_reserved_bytes,
 base_bytes_limit,final_pdf_bytes_limit,fits_index_bytes_limit,certificate_pdf_bytes_limit,
 certificate_payload_bytes_limit,certificate_signature_bytes_limit,archive_budget_bytes,owner_id,lease_until
)
SELECT sqlc.arg(id),d.org_id,d.id,d.article13_notice_epoch_at,d.completion_effective_at,d.finalization_retain_until,d.name,
 d.pdf_storage_key,d.pdf_storage_version_id,d.pdf_sha256,x.source_bytes,sqlc.arg(source_pages),
 sqlc.arg(geometry_pages_payload)::bytea,digest(sqlc.arg(geometry_pages_payload)::bytea,'sha256'),
 sqlc.arg(field_snapshot_payload)::bytea,digest(sqlc.arg(field_snapshot_payload)::bytea,'sha256'),
 sqlc.arg(required_base_pages)::integer[],cardinality(sqlc.arg(required_base_pages)::integer[])+5,
 1+(SELECT count(*)::integer FROM signature_fit_objects o JOIN signature_fit_selections s ON s.preparation_id=o.preparation_id
    JOIN signature_fit_companions c ON c.selection_id=s.id WHERE c.document_id=d.id AND c.org_id=d.org_id)
   +(SELECT count(*)::integer FROM signatures s WHERE s.document_id=d.id AND s.signature_kind<>'manual_pdf_fit_v1'),
 d.signature_fit_reserved_bytes,sqlc.arg(base_bytes_limit),sqlc.arg(final_pdf_bytes_limit),sqlc.arg(fits_index_bytes_limit),
 sqlc.arg(certificate_pdf_bytes_limit),sqlc.arg(certificate_payload_bytes_limit),sqlc.arg(certificate_signature_bytes_limit),
 sqlc.arg(archive_budget_bytes),sqlc.arg(owner_id),sqlc.arg(lease_until)
FROM parent d CROSS JOIN chosen x RETURNING preparation.*;

-- name: GetFittedFinalizationPreparation :one
SELECT * FROM document_finalization_preparations
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id);

-- name: GetFittedFinalizationPreparationForUpdate :one
-- Caller already holds the scoped document lock.
SELECT * FROM document_finalization_preparations
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id) FOR UPDATE;

-- name: GetFittedFinalizationOutputOperationMetadataForUpdate :one
-- Admit memory and external work from bounded metadata before fetching any
-- original body. The materialized dependency locks the parent before the
-- operation. The application must use an independently connected physical
-- session after an uncertain commit; a pooled negative read is not authority.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.status,d.deleted_at FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.org_id,p.document_id,p.ceremony_epoch,p.completion_effective_at,p.retain_until,
 p.source_storage_key,p.source_version_id,p.source_sha256,p.source_bytes,p.source_pages,
 p.required_base_pages,p.expected_outputs,p.expected_references,p.fit_reserved_bytes,
 p.base_bytes_limit,p.final_pdf_bytes_limit,p.fits_index_bytes_limit,p.certificate_pdf_bytes_limit,
 p.certificate_payload_bytes_limit,p.certificate_signature_bytes_limit,p.archive_budget_bytes,
 p.owner_id,p.lease_until,p.attempts,p.status,d.status AS document_status,d.deleted_at AS document_deleted_at,
 p.retention_started_at,p.retention_completed_at,p.publication_commit_attempted_at,p.published_at,
 (p.audit_snapshot_payload IS NOT NULL)::boolean AS has_audit_snapshot,p.audit_snapshot_sha256,
 COALESCE(octet_length(p.audit_snapshot_payload),0)::bigint AS audit_snapshot_bytes,
 (p.certificate_input_payload IS NOT NULL)::boolean AS has_certificate_input,p.certificate_input_sha256,
 COALESCE(octet_length(p.certificate_input_payload),0)::bigint AS certificate_input_bytes
 FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) FOR UPDATE OF p
)
-- Project the locked tuple itself rather than rejoining its pre-wait snapshot.
-- Evaluate the lease clock only after both materialized locks have completed.
SELECT operation.*,(operation.lease_until>clock_timestamp())::boolean AS lease_current FROM operation;

-- name: GetDocumentFittedFinalizationPreparation :one
SELECT * FROM document_finalization_preparations
WHERE document_id=sqlc.arg(document_id) AND org_id=sqlc.arg(org_id)
 AND ceremony_epoch=sqlc.arg(ceremony_epoch) AND completion_effective_at=sqlc.arg(completion_effective_at);

-- name: ListFittedFinalizationPreparationsForRecovery :many
-- Metadata only; fetch one operation/body at a time after authority checks.
SELECT id,org_id,document_id,ceremony_epoch,completion_effective_at,retain_until,
 owner_id,lease_until,attempts,status,retention_started_at,retention_completed_at,
 publication_commit_attempted_at,published_at,created_at,updated_at
FROM document_finalization_preparations
WHERE org_id=sqlc.arg(org_id) AND status<>'published'
ORDER BY lease_until,id LIMIT LEAST(GREATEST(sqlc.arg(limit_count)::integer,1),100);

-- name: ClaimFittedFinalizationPreparationLease :one
-- A bounded owner takeover does not resolve a former SQL session/Put outcome.
-- Recover exact existing pins; quarantine physically unresolved old sessions.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
)
UPDATE document_finalization_preparations p SET owner_id=sqlc.arg(owner_id),lease_until=sqlc.arg(lease_until),
 attempts=p.attempts+1,updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id)
 AND p.document_id=d.id AND p.document_id=sqlc.arg(document_id) AND p.status<>'published'
 AND p.owner_id<>sqlc.arg(owner_id) AND p.lease_until<=clock_timestamp() AND p.attempts<8
 AND sqlc.arg(lease_until)::timestamptz>clock_timestamp()
RETURNING p.*;

-- name: RenewFittedFinalizationPreparationLease :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
)
UPDATE document_finalization_preparations p SET lease_until=sqlc.arg(lease_until),updated_at=clock_timestamp()
FROM parent d WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=d.id
 AND p.document_id=sqlc.arg(document_id) AND p.owner_id=sqlc.arg(owner_id) AND p.status<>'published'
 AND p.lease_until>clock_timestamp() AND sqlc.arg(lease_until)::timestamptz>=p.lease_until
RETURNING p.*;

-- name: FreezeFittedFinalizationAuditSnapshot :one
-- Freeze actual bounded events/chain/issuer/branding context once, before any
-- output producer. This byte commitment is not a self-asserted issuer receipt.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_preparations p
SET audit_snapshot_payload=sqlc.arg(payload)::bytea,audit_snapshot_sha256=digest(sqlc.arg(payload)::bytea,'sha256'),updated_at=clock_timestamp()
FROM operation o WHERE p.id=o.id AND o.status='staging' AND p.audit_snapshot_payload IS NULL
 AND NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id)
RETURNING p.*;

-- name: FreezeFittedFinalizationCertificateInput :one
-- Freeze the EXACT original signed certificate HTML, including schema4/index
-- claims and original audit context, after actual final/index positive readback.
-- Go must parse/bind real HTML claims to the scoped journal/trusted issuer. The
-- certificate_payload output equals these literal bytes; no retry resampling.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_preparations p
SET certificate_input_payload=sqlc.arg(payload)::bytea,certificate_input_sha256=digest(sqlc.arg(payload)::bytea,'sha256'),updated_at=clock_timestamp()
FROM operation o WHERE p.id=o.id AND o.status='staging' AND p.certificate_input_payload IS NULL
 AND EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='final_pdf' AND readback_verified_at IS NOT NULL)
 AND EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='fits_index' AND readback_verified_at IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind IN('certificate_pdf','certificate_payload','certificate_signature'))
RETURNING p.*;

-- name: MarkFittedFinalizationRetentionStarted :one
-- Persist exact completion+7y target before original Object-Locked uploads.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_preparations p SET retention_started_at=clock_timestamp(),updated_at=clock_timestamp()
FROM operation o WHERE p.id=o.id AND o.status='staging' AND p.retention_started_at IS NULL
RETURNING p.*;

-- name: MarkFittedFinalizationPrepared :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_preparations p SET status='prepared',updated_at=clock_timestamp()
FROM operation o WHERE p.id=o.id AND o.status='staging' AND p.audit_snapshot_payload IS NOT NULL AND p.certificate_input_payload IS NOT NULL
 AND (SELECT count(*) FROM document_finalization_outputs WHERE preparation_id=p.id)=p.expected_outputs
 AND NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND (version_id IS NULL OR readback_verified_at IS NULL))
 AND (SELECT count(*) FROM document_finalization_references WHERE preparation_id=p.id)=p.expected_references
RETURNING p.*;

-- name: MarkFittedFinalizationRetentionComplete :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_preparations p SET retention_completed_at=clock_timestamp(),updated_at=clock_timestamp()
FROM operation o WHERE p.id=o.id AND o.status='prepared' AND p.retention_started_at IS NOT NULL AND p.retention_completed_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND retention_completed_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM document_finalization_references WHERE preparation_id=p.id AND retention_completed_at IS NULL)
 AND EXISTS(SELECT 1 FROM document_finalization_intents WHERE fitted_preparation_id=p.id AND retention_completed_at IS NOT NULL)
RETURNING p.*;

-- name: MarkFittedFinalizationPublicationAttempt :one
-- Commit before the publication transaction. Unknown commit requires a
-- physically fresh exact read; absence on an unresolved session is not proof.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_preparations p SET publication_commit_attempted_at=clock_timestamp(),updated_at=clock_timestamp()
FROM operation o WHERE p.id=o.id AND o.status='prepared' AND p.retention_completed_at IS NOT NULL AND p.publication_commit_attempted_at IS NULL
RETURNING p.*;

-- name: MarkFittedFinalizationPublished :one
-- Execute AFTER CompleteFittedDocumentFinalization in the SAME atomic SQL
-- transaction, then delete46 intent. Deferred pairing prevents partial commit.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_preparations p SET status='published',published_at=clock_timestamp(),updated_at=clock_timestamp()
FROM operation o WHERE p.id=o.id AND o.status='prepared' AND p.retention_completed_at IS NOT NULL
 AND p.publication_commit_attempted_at IS NOT NULL AND p.published_at IS NULL
 AND EXISTS(SELECT 1 FROM documents d WHERE d.id=p.document_id AND d.org_id=p.org_id AND d.status='completed' AND d.fits_index_preparation_id=p.id)
RETURNING p.*;

-- name: ReserveFittedFinalizationOutput :one
-- The original admitted provider body is stored and digest-checked BEFORE its
-- one-way upload attempt. A conflict is a read/reconcile event, never overwrite.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
INSERT INTO document_finalization_outputs AS asset(preparation_id,kind,page,storage_key,sha256,bytes,content_type,payload)
SELECT o.id,sqlc.arg(kind),sqlc.arg(page),sqlc.arg(storage_key),digest(sqlc.arg(payload)::bytea,'sha256'),
 octet_length(sqlc.arg(payload)::bytea),sqlc.arg(content_type),sqlc.arg(payload)::bytea FROM operation o WHERE o.status='staging'
RETURNING asset.preparation_id,asset.kind,asset.page,asset.storage_key,asset.sha256,asset.bytes,asset.content_type,asset.upload_attempted_at,asset.upload_owner_id,
 asset.version_id,asset.readback_verified_at,asset.retention_started_at,asset.retention_completed_at;

-- name: GetFittedFinalizationOutput :one
-- Fetch a single bounded original body; never load every body into one slice.
SELECT o.* FROM document_finalization_outputs o JOIN document_finalization_preparations p ON p.id=o.preparation_id
WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND o.kind=sqlc.arg(kind) AND o.page=sqlc.arg(page);

-- name: GetFittedFinalizationOutputMetadata :one
-- Use before global admission. This projection deliberately excludes payload.
-- Caller holds the parent/operation lock through any admitted body fetch or IO.
SELECT o.preparation_id,o.kind,o.page,o.storage_key,o.sha256,o.bytes,o.content_type,o.upload_attempted_at,o.upload_owner_id,
 o.version_id,o.readback_verified_at,o.retention_started_at,o.retention_completed_at
FROM document_finalization_outputs o JOIN document_finalization_preparations p ON p.id=o.preparation_id
WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND o.kind=sqlc.arg(kind) AND o.page=sqlc.arg(page) FOR UPDATE OF o;

-- name: ListFittedFinalizationOutputs :many
SELECT o.preparation_id,o.kind,o.page,o.storage_key,o.sha256,o.bytes,o.content_type,o.upload_attempted_at,o.upload_owner_id,
 o.version_id,o.readback_verified_at,o.retention_started_at,o.retention_completed_at
FROM document_finalization_outputs o JOIN document_finalization_preparations p ON p.id=o.preparation_id
WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
ORDER BY CASE o.kind WHEN 'base_pdf' THEN 0 WHEN 'final_pdf' THEN 1 WHEN 'fits_index' THEN 2 WHEN 'certificate_payload' THEN 3 WHEN 'certificate_signature' THEN 4 ELSE 5 END,o.page;

-- name: MarkFittedFinalizationOutputRetentionStarted :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_outputs asset SET retention_started_at=clock_timestamp()
FROM operation o JOIN document_finalization_preparations p ON p.id=o.id
WHERE asset.preparation_id=o.id AND asset.kind=sqlc.arg(kind) AND asset.page=sqlc.arg(page)
 AND asset.retention_started_at IS NULL AND p.retention_started_at IS NOT NULL
RETURNING asset.preparation_id,asset.kind,asset.page,asset.storage_key,asset.sha256,asset.bytes,asset.content_type,
 asset.upload_attempted_at,asset.upload_owner_id,asset.version_id,asset.readback_verified_at,asset.retention_started_at,asset.retention_completed_at;

-- name: MarkFittedFinalizationOutputOriginalUploadAttempt :one
-- Only a returned, durably committed NEW marker authorizes the sole Put. A
-- timeout/commit error requires fresh-session resolution; no automatic retry.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_outputs asset SET upload_attempted_at=clock_timestamp(),upload_owner_id=o.owner_id
FROM operation o JOIN document_finalization_preparations p ON p.id=o.id
WHERE asset.preparation_id=o.id AND asset.kind=sqlc.arg(kind) AND asset.page=sqlc.arg(page) AND o.status='staging'
 AND asset.upload_attempted_at IS NULL AND asset.retention_started_at IS NOT NULL AND p.retention_started_at IS NOT NULL
 AND asset.version_id IS NULL AND asset.readback_verified_at IS NULL
RETURNING asset.preparation_id,asset.kind,asset.page,asset.storage_key,asset.sha256,asset.bytes,asset.content_type,
 asset.upload_attempted_at,asset.upload_owner_id,asset.version_id,asset.readback_verified_at,asset.retention_started_at,asset.retention_completed_at;

-- name: PinFittedFinalizationOutputVersion :one
-- Preserve a positive provider pin even when post-Put checks/cancellation fail.
-- Readback still requires exact bounded bytes/MIME/SSE before any next stage.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_outputs asset SET version_id=sqlc.arg(version_id)
FROM operation o WHERE asset.preparation_id=o.id AND asset.kind=sqlc.arg(kind) AND asset.page=sqlc.arg(page)
 AND asset.upload_attempted_at IS NOT NULL AND asset.version_id IS NULL
RETURNING asset.preparation_id,asset.kind,asset.page,asset.storage_key,asset.sha256,asset.bytes,asset.content_type,
 asset.upload_attempted_at,asset.upload_owner_id,asset.version_id,asset.readback_verified_at,asset.retention_started_at,asset.retention_completed_at;

-- name: MarkFittedFinalizationOutputReadbackVerified :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_outputs asset SET readback_verified_at=clock_timestamp()
FROM operation o WHERE asset.preparation_id=o.id AND asset.kind=sqlc.arg(kind) AND asset.page=sqlc.arg(page)
 AND asset.version_id=sqlc.arg(version_id) AND asset.upload_attempted_at IS NOT NULL AND asset.readback_verified_at IS NULL
RETURNING asset.preparation_id,asset.kind,asset.page,asset.storage_key,asset.sha256,asset.bytes,asset.content_type,
 asset.upload_attempted_at,asset.upload_owner_id,asset.version_id,asset.readback_verified_at,asset.retention_started_at,asset.retention_completed_at;

-- name: MarkFittedFinalizationOutputRetentionComplete :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_outputs asset SET retention_completed_at=clock_timestamp()
FROM operation o WHERE asset.preparation_id=o.id AND asset.kind=sqlc.arg(kind) AND asset.page=sqlc.arg(page)
 AND asset.version_id=sqlc.arg(version_id) AND asset.retention_started_at IS NOT NULL AND asset.readback_verified_at IS NOT NULL
 AND asset.retention_completed_at IS NULL
RETURNING asset.preparation_id,asset.kind,asset.page,asset.storage_key,asset.sha256,asset.bytes,asset.content_type,
 asset.upload_attempted_at,asset.upload_owner_id,asset.version_id,asset.readback_verified_at,asset.retention_started_at,asset.retention_completed_at;

-- name: CaptureFittedFinalizationReferences :many
-- Derive complete identities from the guarded source, real85 companion-selected
-- inventory and frozen legacy basis. Caller does not supply artifact pins.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
), refs AS (
 SELECT p.id AS preparation_id,'source'::text AS kind,NULL::uuid AS signature_id,NULL::uuid AS selection_id,
  0::integer AS page,p.source_storage_key AS storage_key,p.source_version_id AS version_id,p.source_sha256 AS sha256,
  p.source_bytes AS bytes,'application/pdf'::text AS content_type,p.document_id AS owner_key
 FROM document_finalization_preparations p JOIN operation op ON op.id=p.id WHERE op.status='staging'
 UNION ALL
 SELECT p.id,CASE o.kind WHEN 'span' THEN 'fit_span' WHEN 'page' THEN 'fit_page' ELSE 'fit_manifest' END,
  c.signature_id,x.id,o.page,o.storage_key,o.version_id,o.sha256,o.bytes,o.content_type,c.signature_id
 FROM document_finalization_preparations p JOIN operation op ON op.id=p.id
 JOIN signature_fit_companions c ON c.document_id=p.document_id AND c.org_id=p.org_id
 JOIN signature_fit_selections x ON x.id=c.selection_id JOIN signature_fit_objects o ON o.preparation_id=x.preparation_id
 WHERE op.status='staging' AND o.readback_verified_at IS NOT NULL AND o.cleanup_completed_at IS NULL
 UNION ALL
 SELECT p.id,'legacy_span', (e.value->>'ID')::uuid,NULL::uuid,0,
  e.value->'Object'->>'key',e.value->'Object'->>'version_id',decode(e.value->'Object'->>'sha256','hex'),
  (e.value->'Object'->>'bytes')::bigint,'text/html',(e.value->>'ID')::uuid
 FROM document_finalization_preparations p JOIN operation op ON op.id=p.id
 CROSS JOIN LATERAL jsonb_array_elements(convert_from(p.field_snapshot_payload,'UTF8')::jsonb->'Legacy') e(value)
 WHERE op.status='staging'
)
INSERT INTO document_finalization_references AS asset(preparation_id,kind,signature_id,selection_id,page,storage_key,version_id,sha256,bytes,content_type,owner_key)
SELECT refs.preparation_id,refs.kind,refs.signature_id,refs.selection_id,refs.page,refs.storage_key,refs.version_id,refs.sha256,refs.bytes,refs.content_type,refs.owner_key FROM refs
RETURNING asset.*;

-- name: ListFittedFinalizationReferences :many
SELECT asset.* FROM document_finalization_references asset JOIN document_finalization_preparations p ON p.id=asset.preparation_id
WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
ORDER BY CASE asset.kind WHEN 'source' THEN 0 WHEN 'fit_span' THEN 1 WHEN 'fit_page' THEN 2 WHEN 'fit_manifest' THEN 3 ELSE 4 END,asset.owner_key,asset.page;

-- name: MarkFittedFinalizationReferenceRetentionStarted :one
-- Earlier prepared46 intent start establishes the final retention extension
-- target for every exact source/span/package/manifest/legacy version.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_references asset SET retention_started_at=clock_timestamp()
FROM operation o WHERE asset.preparation_id=o.id AND o.status='prepared'
 AND asset.kind=sqlc.arg(kind) AND asset.owner_key=sqlc.arg(owner_key) AND asset.page=sqlc.arg(page)
 AND asset.version_id=sqlc.arg(version_id) AND asset.retention_started_at IS NULL
 AND EXISTS(SELECT 1 FROM document_finalization_intents WHERE fitted_preparation_id=o.id AND retention_started_at IS NOT NULL)
RETURNING asset.*;

-- name: MarkFittedFinalizationReferenceRetentionComplete :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_references asset SET retention_completed_at=clock_timestamp()
FROM operation o WHERE asset.preparation_id=o.id AND o.status='prepared'
 AND asset.kind=sqlc.arg(kind) AND asset.owner_key=sqlc.arg(owner_key) AND asset.page=sqlc.arg(page)
 AND asset.version_id=sqlc.arg(version_id) AND asset.retention_started_at IS NOT NULL AND asset.retention_completed_at IS NULL
 AND EXISTS(SELECT 1 FROM document_finalization_intents WHERE fitted_preparation_id=o.id AND retention_started_at IS NOT NULL)
RETURNING asset.*;

-- name: CreateFittedDocumentFinalizationIntent :one
-- Copy the exact known pins from the complete journal, not request arguments.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
INSERT INTO document_finalization_intents AS intent(document_id,org_id,mode,completion_effective_at,retain_until,
 final_pdf_key,final_pdf_sha256,final_pdf_version_id,audit_cert_key,audit_cert_sha256,audit_cert_version_id,
 audit_payload_key,audit_payload_sha256,audit_payload_version_id,audit_signature_key,audit_signature_sha256,audit_signature_version_id,
 evidence_version_pins_required,fitted_preparation_id,fits_index_storage_key,fits_index_version_id,fits_index_sha256,fits_index_bytes)
SELECT p.document_id,p.org_id,'signature',p.completion_effective_at,p.retain_until,
 f.storage_key,f.sha256,f.version_id,c.storage_key,c.sha256,c.version_id,
 b.storage_key,b.sha256,b.version_id,s.storage_key,s.sha256,s.version_id,
 TRUE,p.id,i.storage_key,i.version_id,i.sha256,i.bytes
FROM operation o JOIN document_finalization_preparations p ON p.id=o.id
JOIN document_finalization_outputs f ON f.preparation_id=p.id AND f.kind='final_pdf' AND f.readback_verified_at IS NOT NULL
JOIN document_finalization_outputs c ON c.preparation_id=p.id AND c.kind='certificate_pdf' AND c.readback_verified_at IS NOT NULL
JOIN document_finalization_outputs b ON b.preparation_id=p.id AND b.kind='certificate_payload' AND b.readback_verified_at IS NOT NULL
JOIN document_finalization_outputs s ON s.preparation_id=p.id AND s.kind='certificate_signature' AND s.readback_verified_at IS NOT NULL
JOIN document_finalization_outputs i ON i.preparation_id=p.id AND i.kind='fits_index' AND i.readback_verified_at IS NOT NULL
WHERE o.status='prepared' RETURNING intent.*;

-- name: MarkFittedDocumentFinalizationIntentRetentionStarted :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_intents intent SET retention_started_at=clock_timestamp(),updated_at=clock_timestamp()
FROM operation o JOIN document_finalization_preparations p ON p.id=o.id
WHERE intent.fitted_preparation_id=o.id AND intent.org_id=sqlc.arg(org_id) AND intent.document_id=sqlc.arg(document_id)
 AND o.status='prepared' AND p.retention_started_at IS NOT NULL AND intent.retention_started_at IS NULL
RETURNING intent.*;

-- name: MarkFittedDocumentFinalizationIntentRetentionComplete :one
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE document_finalization_intents intent SET retention_completed_at=clock_timestamp(),updated_at=clock_timestamp(),attempts=intent.attempts+1,last_error=NULL
FROM operation o WHERE intent.fitted_preparation_id=o.id AND intent.org_id=sqlc.arg(org_id) AND intent.document_id=sqlc.arg(document_id)
 AND o.status='prepared' AND intent.retention_started_at IS NOT NULL AND intent.retention_completed_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=o.id AND retention_completed_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM document_finalization_references WHERE preparation_id=o.id AND retention_completed_at IS NULL)
RETURNING intent.*;

-- name: CompleteFittedDocumentFinalization :one
-- Existing legacy completion cannot publish a flagged document:86 requires
-- its exact immutable index/preparation pair. Execute MarkPublished next in
-- this same transaction before token/reminder/event terminal work commits.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_finalization_preparations p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id) FOR UPDATE OF d
), operation AS MATERIALIZED (
 SELECT p.id,p.owner_id,p.status FROM document_finalization_preparations p JOIN parent d ON d.id=p.document_id
 WHERE p.id=sqlc.arg(preparation_id) AND p.org_id=sqlc.arg(org_id) AND p.document_id=sqlc.arg(document_id)
 AND p.owner_id=sqlc.arg(owner_id) AND p.lease_until>clock_timestamp() AND p.status<>'published' FOR UPDATE OF p
)
UPDATE documents d SET final_pdf_key=intent.final_pdf_key,final_pdf_sha=intent.final_pdf_sha256,final_pdf_version_id=intent.final_pdf_version_id,
 audit_cert_key=intent.audit_cert_key,audit_cert_sha256=intent.audit_cert_sha256,audit_cert_version_id=intent.audit_cert_version_id,
 audit_payload_key=intent.audit_payload_key,audit_payload_sha256=intent.audit_payload_sha256,audit_payload_version_id=intent.audit_payload_version_id,
 audit_signature_key=intent.audit_signature_key,audit_signature_sha256=intent.audit_signature_sha256,audit_signature_version_id=intent.audit_signature_version_id,
 fits_index_preparation_id=p.id,fits_index_storage_key=intent.fits_index_storage_key,fits_index_version_id=intent.fits_index_version_id,
 fits_index_sha256=intent.fits_index_sha256,fits_index_bytes=intent.fits_index_bytes,
 completed_at=d.completion_effective_at,status='completed',updated_at=clock_timestamp()
FROM operation o JOIN document_finalization_preparations p ON p.id=o.id
JOIN document_finalization_intents intent ON intent.fitted_preparation_id=p.id AND intent.org_id=p.org_id AND intent.document_id=p.document_id
WHERE d.id=p.document_id AND d.org_id=p.org_id AND d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND d.status='finalizing' AND d.fits_index_required AND d.completion_effective_at_bound AND d.evidence_version_pins_required
 AND d.completion_effective_at=p.completion_effective_at AND d.finalization_retain_until=p.retain_until
 AND o.status='prepared' AND p.retention_completed_at IS NOT NULL AND p.publication_commit_attempted_at IS NOT NULL
 AND intent.retention_completed_at IS NOT NULL AND intent.evidence_version_pins_required
RETURNING d.*;

-- name: GetCompletedFittedFinalization :one
-- Separate exact immutable completed callback for schema4/export recovery.
-- Mandatory app verification reads signed index using these opaque pins and a
-- trusted issuer key. Never infer/regenerate it from hot DSR signatures/fields.
SELECT d.id,d.org_id,d.fits_index_required,d.fits_index_preparation_id,d.fits_index_storage_key,d.fits_index_version_id,d.fits_index_sha256,d.fits_index_bytes,
 d.final_pdf_key,d.final_pdf_sha,d.final_pdf_version_id,d.audit_cert_key,d.audit_cert_sha256,d.audit_cert_version_id,
 d.audit_payload_key,d.audit_payload_sha256,d.audit_payload_version_id,d.audit_signature_key,d.audit_signature_sha256,d.audit_signature_version_id,
 p.original_document_name,p.ceremony_epoch,p.completion_effective_at,p.retain_until,p.field_snapshot_sha256,p.geometry_sha256,
 f.bytes AS final_pdf_bytes,p.published_at
FROM documents d JOIN document_finalization_preparations p ON p.id=d.fits_index_preparation_id AND p.org_id=d.org_id AND p.document_id=d.id
JOIN document_finalization_outputs f ON f.preparation_id=p.id AND f.kind='final_pdf'
WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id) AND d.status='completed' AND d.fits_index_required
 AND p.status='published' AND p.published_at IS NOT NULL AND p.retention_completed_at IS NOT NULL
 AND d.completed_at=p.completion_effective_at AND d.finalization_retain_until=p.retain_until
 AND f.retention_completed_at IS NOT NULL AND f.readback_verified_at IS NOT NULL
 AND ROW(d.final_pdf_key,d.final_pdf_sha,d.final_pdf_version_id) IS NOT DISTINCT FROM ROW(f.storage_key,f.sha256,f.version_id)
 AND EXISTS(SELECT 1 FROM document_finalization_outputs i WHERE i.preparation_id=p.id AND i.kind='fits_index'
  AND i.retention_completed_at IS NOT NULL AND i.readback_verified_at IS NOT NULL
  AND ROW(d.fits_index_storage_key,d.fits_index_version_id,d.fits_index_sha256,d.fits_index_bytes) IS NOT DISTINCT FROM ROW(i.storage_key,i.version_id,i.sha256,i.bytes))
 AND EXISTS(SELECT 1 FROM document_finalization_outputs c WHERE c.preparation_id=p.id AND c.kind='certificate_pdf'
  AND c.retention_completed_at IS NOT NULL AND c.readback_verified_at IS NOT NULL
  AND ROW(d.audit_cert_key,d.audit_cert_sha256,d.audit_cert_version_id) IS NOT DISTINCT FROM ROW(c.storage_key,c.sha256,c.version_id))
 AND EXISTS(SELECT 1 FROM document_finalization_outputs b WHERE b.preparation_id=p.id AND b.kind='certificate_payload'
  AND b.retention_completed_at IS NOT NULL AND b.readback_verified_at IS NOT NULL
  AND ROW(d.audit_payload_key,d.audit_payload_sha256,d.audit_payload_version_id) IS NOT DISTINCT FROM ROW(b.storage_key,b.sha256,b.version_id))
 AND EXISTS(SELECT 1 FROM document_finalization_outputs s WHERE s.preparation_id=p.id AND s.kind='certificate_signature'
  AND s.retention_completed_at IS NOT NULL AND s.readback_verified_at IS NOT NULL
  AND ROW(d.audit_signature_key,d.audit_signature_sha256,d.audit_signature_version_id) IS NOT DISTINCT FROM ROW(s.storage_key,s.sha256,s.version_id));

-- name: ListFittedFinalizationPrivacyInventory :many
-- Metadata inventory only, including86 raw durable PII bodies and85 unselected
-- positive/unknown uploads. Empty history never proves an attempted row erased.
-- A nonempty inventory requires real controller policy before DSR disposition;
-- this API provides no invented hold exception, discard or erasure mutation.
WITH scoped AS MATERIALIZED (
 SELECT doc.id,doc.org_id,doc.fits_index_required FROM documents doc WHERE doc.id=sqlc.arg(document_id) AND doc.org_id=sqlc.arg(org_id)
), inventory AS (
 SELECT 'fitted_requirement'::text AS inventory_kind,d.id AS operation_id,'document'::text AS artifact_kind,0::integer AS page,
  NULL::text AS storage_key,NULL::text AS version_id,NULL::bytea AS sha256,0::bigint AS bytes,NULL::timestamptz AS upload_attempted_at,
  NULL::timestamptz AS readback_verified_at,NULL::timestamptz AS retention_completed_at,FALSE AS has_durable_payload,FALSE AS unresolved_commit
 FROM scoped d WHERE d.fits_index_required
 UNION ALL
 SELECT 'finalization_basis',p.id,'basis',0,NULL,NULL,p.field_snapshot_sha256,
  octet_length(p.field_snapshot_payload)::bigint+octet_length(p.geometry_pages_payload)::bigint+
   COALESCE(octet_length(p.audit_snapshot_payload),0)::bigint+COALESCE(octet_length(p.certificate_input_payload),0)::bigint,
  NULL,NULL,p.retention_completed_at,TRUE,p.publication_commit_attempted_at IS NOT NULL AND p.status<>'published'
 FROM document_finalization_preparations p JOIN scoped d ON d.id=p.document_id AND d.org_id=p.org_id
 UNION ALL
 SELECT 'finalization_output',p.id,a.kind,a.page,a.storage_key,a.version_id,a.sha256,a.bytes,a.upload_attempted_at,a.readback_verified_at,a.retention_completed_at,TRUE,FALSE
 FROM document_finalization_outputs a JOIN document_finalization_preparations p ON p.id=a.preparation_id JOIN scoped d ON d.id=p.document_id AND d.org_id=p.org_id
 UNION ALL
 SELECT 'finalization_reference',p.id,a.kind,a.page,a.storage_key,a.version_id,a.sha256,a.bytes,NULL,NULL,a.retention_completed_at,FALSE,FALSE
 FROM document_finalization_references a JOIN document_finalization_preparations p ON p.id=a.preparation_id JOIN scoped d ON d.id=p.document_id AND d.org_id=p.org_id
 UNION ALL
 SELECT 'fit_preparation',p.id,'authority',0,p.source_storage_key,p.source_version_id,p.authority_sha256,p.reserved_bytes,
  NULL,NULL,NULL,FALSE,p.selection_commit_attempted_at IS NOT NULL AND p.selection_not_committed_at IS NULL AND NOT EXISTS(SELECT 1 FROM signature_fit_selections WHERE preparation_id=p.id)
 FROM signature_fit_preparations p JOIN scoped d ON d.id=p.document_id AND d.org_id=p.org_id WHERE p.status<>'cleaned'
 UNION ALL
 SELECT 'fit_object',p.id,a.kind,a.page,a.storage_key,a.version_id,a.sha256,a.bytes,a.upload_attempted_at,a.readback_verified_at,NULL,FALSE,FALSE
 FROM signature_fit_objects a JOIN signature_fit_preparations p ON p.id=a.preparation_id JOIN scoped d ON d.id=p.document_id AND d.org_id=p.org_id
 WHERE a.cleanup_completed_at IS NULL
)
SELECT inventory_kind,operation_id,artifact_kind,count(*)::bigint AS object_count,sum(bytes)::bigint AS total_bytes,
 count(*) FILTER(WHERE has_durable_payload)::bigint AS durable_payload_count,
 count(*) FILTER(WHERE upload_attempted_at IS NOT NULL AND version_id IS NULL)::bigint AS unresolved_attempt_count,
 count(*) FILTER(WHERE unresolved_commit)::bigint AS unresolved_commit_count,
 count(*) FILTER(WHERE version_id IS NOT NULL)::bigint AS positive_pin_count,
 count(*) FILTER(WHERE retention_completed_at IS NOT NULL)::bigint AS retention_completed_count
FROM inventory GROUP BY inventory_kind,operation_id,artifact_kind ORDER BY operation_id,inventory_kind,artifact_kind;
