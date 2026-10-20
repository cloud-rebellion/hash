-- name: CreateDocumentPackageSendAttemptV1 :one
-- Actual immutable scalar capture fields; never materialize manifest/report
-- bodies for binding. The native caller owns these exact expectations.
WITH candidate AS MATERIALIZED (
 SELECT c.package_id,c.revision,c.previous_revision,c.org_id,c.document_id,c.captured_root_updated_at,
 c.captured_draft_generation,octet_length(c.manifest)::integer AS manifest_bytes,
 c.manifest_sha256,c.legal_commitment_sha256,c.member_count,c.pdf_bytes,c.pdf_pages,c.created_by,
 GREATEST(statement_timestamp(),clock_timestamp(),COALESCE(d.article13_notice_epoch_at+interval '1 microsecond','-infinity'::timestamptz)) AS epoch
 FROM document_package_captures_v1 c JOIN documents d ON d.id=c.document_id AND d.org_id=c.org_id
 WHERE c.package_id=sqlc.arg(package_id)::uuid AND c.revision=sqlc.arg(capture_revision)::bigint
 AND c.org_id=sqlc.arg(org_id)::uuid AND c.document_id=sqlc.arg(document_id)::uuid
 AND c.captured_root_updated_at=sqlc.arg(expected_root_updated_at)::timestamptz
 AND c.captured_draft_generation=sqlc.arg(expected_draft_generation)::bigint
 AND c.previous_revision=sqlc.arg(expected_previous_revision)::bigint
 AND octet_length(c.manifest)=sqlc.arg(expected_manifest_bytes)::integer
 AND c.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
 AND c.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND c.member_count=sqlc.arg(expected_member_count)::smallint
 AND c.pdf_bytes=sqlc.arg(expected_pdf_bytes)::bigint AND c.pdf_pages=sqlc.arg(expected_pdf_pages)::integer
 AND c.created_by=sqlc.arg(actor_user_id)::uuid
)
INSERT INTO document_package_send_attempts_v1(attempt_id,org_id,document_id,package_id,capture_revision,previous_revision,
 manifest_bytes,member_count,pdf_bytes,pdf_pages,captured_root_updated_at,captured_draft_generation,
 manifest_sha256,legal_commitment_sha256,actor_user_id,article13_notice_epoch_at,retain_until)
SELECT sqlc.arg(attempt_id)::uuid,org_id,document_id,package_id,revision,previous_revision,manifest_bytes,member_count,pdf_bytes,pdf_pages,
 captured_root_updated_at,captured_draft_generation,manifest_sha256,legal_commitment_sha256,created_by,epoch,hash_evidence_retain_until(epoch,7)
FROM candidate RETURNING *;

-- name: CreateDocumentPackageSealingIntentV1 :one
-- A new exact bound intent, never a NULL -> bound retrofit of legacy state.
INSERT INTO send_sealing_intents(document_id,org_id,actor_user_id,actor_email,actor_ip,via,tool,
 article13_notice_epoch_at,retain_until,package_send_attempt_id)
SELECT a.document_id,a.org_id,a.actor_user_id,u.email,sqlc.arg(actor_ip)::text,sqlc.arg(via)::text,sqlc.arg(tool)::text,
 a.article13_notice_epoch_at,a.retain_until,a.attempt_id
FROM document_package_send_attempts_v1 a JOIN users u ON u.id=a.actor_user_id AND u.org_id=a.org_id
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.terminal_outcome IS NULL
RETURNING *;

-- name: InspectDocumentPackageSendAttemptV1 :one
-- Bounded exact-attempt observation. Absence never grants replay permission.
SELECT a.*,(EXISTS(SELECT 1 FROM send_sealing_intents i WHERE i.package_send_attempt_id=a.attempt_id
 AND i.org_id=a.org_id AND i.document_id=a.document_id))::boolean AS has_active_intent
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid;

-- name: MarkDocumentPackageSendRetentionStartedV1 :one
UPDATE send_sealing_intents i SET retention_started_at=COALESCE(i.retention_started_at,clock_timestamp()),updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
 AND i.retention_completed_at IS NULL
RETURNING i.*;

-- name: MarkDocumentPackageSendRetentionCompleteV1 :one
UPDATE send_sealing_intents i SET retention_completed_at=COALESCE(i.retention_completed_at,clock_timestamp()),
 attempts=i.attempts+1,last_error=NULL,updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
 AND i.retention_started_at IS NOT NULL
RETURNING i.*;

-- name: SynchronizeDocumentPackageSendRetentionV1 :one
UPDATE document_package_send_attempts_v1 a SET retention_started_at=i.retention_started_at,retention_completed_at=i.retention_completed_at
FROM send_sealing_intents i
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
RETURNING a.*;

-- name: TerminalizeDocumentPackageSendAttemptV1 :one
UPDATE document_package_send_attempts_v1 SET terminal_outcome=sqlc.arg(outcome)::text,terminal_at=clock_timestamp()
WHERE attempt_id=sqlc.arg(attempt_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND document_id=sqlc.arg(document_id)::uuid
 AND manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND terminal_outcome IS NULL AND sqlc.arg(outcome)::text IN ('completed','aborted')
RETURNING *;

-- name: DeleteDocumentPackageSealingIntentV1 :execrows
DELETE FROM send_sealing_intents i USING document_package_send_attempts_v1 a
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NOT NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id;

-- name: AbortDocumentPackageSendSealingV1 :execrows
UPDATE documents d SET status='draft',updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a JOIN send_sealing_intents i
 ON i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NULL AND i.retention_started_at IS NULL AND i.retention_completed_at IS NULL
 AND d.id=a.document_id AND d.org_id=a.org_id AND d.status='sealing' AND d.deleted_at IS NULL;

-- name: CompleteDocumentPackageSendSealingV1 :one
UPDATE documents d SET status='sent',sent_at=a.article13_notice_epoch_at,article13_notice_epoch_at=a.article13_notice_epoch_at,
 article13_notice_schema='hash-a13-2026-08-31',article13_notice_epoch_v61_committed=TRUE,updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a JOIN send_sealing_intents i
 ON i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NULL AND i.retention_started_at IS NOT NULL AND i.retention_completed_at IS NOT NULL
 AND a.retention_started_at=i.retention_started_at AND a.retention_completed_at=i.retention_completed_at
 AND d.id=a.document_id AND d.org_id=a.org_id AND d.status='sealing' AND d.deleted_at IS NULL AND d.evidence_version_pins_required
 AND (d.article13_notice_epoch_at IS NULL OR a.article13_notice_epoch_at>d.article13_notice_epoch_at)
RETURNING d.*;

-- name: HasDocumentPackageSendHistoryV1 :one
SELECT EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE org_id=sqlc.arg(org_id)::uuid AND document_id=sqlc.arg(document_id)::uuid)::boolean;

-- name: InspectDocumentPackageSendAttemptStateV1 :one
-- One bounded MVCC snapshot of exact attempt/capture/intent scalars, after the
-- native owner holds root and immutable subject privacy fences. No live annex
-- rows or manifest/report/text bodies; absence grants no replay permission.
SELECT a.*,c.created_at AS capture_created_at,
 (c.package_id IS NOT NULL AND c.previous_revision=a.previous_revision
 AND c.captured_root_updated_at=a.captured_root_updated_at
 AND c.captured_draft_generation=a.captured_draft_generation
 AND octet_length(c.manifest)=a.manifest_bytes AND c.manifest_sha256=a.manifest_sha256
 AND c.legal_commitment_sha256=a.legal_commitment_sha256 AND c.member_count=a.member_count
 AND c.pdf_bytes=a.pdf_bytes AND c.pdf_pages=a.pdf_pages AND c.created_by=a.actor_user_id)::boolean AS exact_capture,
 i.package_send_attempt_id AS intent_attempt_id,i.actor_user_id AS intent_actor_user_id,
 i.presign_execution_id AS intent_presign_execution_id,
 i.article13_notice_epoch_at AS intent_article13_notice_epoch_at,i.retain_until AS intent_retain_until,
 i.retention_started_at AS intent_retention_started_at,i.retention_completed_at AS intent_retention_completed_at
FROM document_package_send_attempts_v1 a
LEFT JOIN document_package_captures_v1 c ON c.package_id=a.package_id AND c.revision=a.capture_revision
 AND c.org_id=a.org_id AND c.document_id=a.document_id
LEFT JOIN send_sealing_intents i ON i.package_send_attempt_id=a.attempt_id
 AND i.org_id=a.org_id AND i.document_id=a.document_id
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid
 AND a.document_id=sqlc.arg(document_id)::uuid;

-- name: ListDocumentPackageSendAttemptSubjectsV1 :many
-- Scalar immutable privacy subjects only; never read member reports, storage
-- keys, current source rows or manifest bodies during recovery inspection.
SELECT m.member_position,m.member_document_id
FROM document_package_send_attempts_v1 a
JOIN document_package_captures_v1 c ON c.package_id=a.package_id AND c.revision=a.capture_revision
 AND c.org_id=a.org_id AND c.document_id=a.document_id
JOIN document_package_capture_members_v1 m ON m.package_id=c.package_id AND m.revision=c.revision AND m.org_id=c.org_id
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid
 AND a.document_id=sqlc.arg(document_id)::uuid AND c.package_id=sqlc.arg(package_id)::uuid
 AND c.revision=sqlc.arg(capture_revision)::bigint AND c.member_count=sqlc.arg(member_count)::smallint
 AND c.manifest_sha256=sqlc.arg(manifest_sha256)::bytea AND c.legal_commitment_sha256=sqlc.arg(legal_commitment_sha256)::bytea
ORDER BY m.member_position LIMIT 18;

-- name: ListPendingDocumentPackageSendRecoveryV1 :many
-- Queue coordinates select work only. Authorization and exact persisted state
-- are checked independently before recovery; no joined row may hide a job.
SELECT attempt_id,org_id,document_id,created_at
FROM document_package_send_attempts_v1
WHERE terminal_outcome IS NULL
 AND hash_package_send_recovery_queue_version_v1()=1
 AND (created_at,attempt_id)>(sqlc.arg(after_created_at)::timestamptz,sqlc.arg(after_attempt_id)::uuid)
ORDER BY created_at,attempt_id LIMIT 50;
