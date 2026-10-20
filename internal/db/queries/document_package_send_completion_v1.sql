-- name: GetDocumentPackageSendCompletionVersionV1 :one
-- The genuine caller checks schema readiness before provider/preparation work.
SELECT hash_package_send_completion_version_v1()::integer AS version;

-- name: InsertDocumentPackageInitialInviteReceiptV1 :one
-- Native fixed output authority supplied the actual outbox ID. Tokens and
-- message/event commitments are derived here, never accepted as caller proof.
WITH root AS MATERIALIZED (
 SELECT id,org_id FROM documents WHERE id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid FOR UPDATE NOWAIT
), candidate AS MATERIALIZED (
 SELECT a.attempt_id,a.org_id,a.document_id,r.id AS recipient_id,e.id AS email_delivery_id,
  hash_package_send_event_id_v1(a.attempt_id,'recipient.invited',r.id) AS invited_event_id,
  r.magic_token_hash AS token_hash,r.magic_token_expires_at AS token_expires_at,
  hash_package_send_message_sha256_v1(e.id) AS message_sha256
 FROM root JOIN document_package_send_attempts_v1 a ON a.document_id=root.id AND a.org_id=root.org_id
 JOIN recipients r ON r.document_id=a.document_id AND r.id=sqlc.arg(recipient_id)::uuid
 JOIN email_deliveries e ON e.id=sqlc.arg(email_delivery_id)::uuid
 WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.terminal_outcome IS NULL
  AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
  AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
  AND hash_package_send_completion_version_v1()=1
)
INSERT INTO document_package_send_initial_invite_receipts_v1(attempt_id,org_id,document_id,recipient_id,email_delivery_id,
 invited_event_id,invited_event_row_sha256,token_hash,token_expires_at,message_sha256)
SELECT c.attempt_id,c.org_id,c.document_id,c.recipient_id,c.email_delivery_id,c.invited_event_id,e.row_hash,c.token_hash,c.token_expires_at,c.message_sha256
FROM candidate c JOIN events e ON e.id=c.invited_event_id
RETURNING *;

-- name: RecordDocumentPackageSendCompletionV1 :one
-- All actual initial invite/audit effects precede this fixed scalar summary in
-- the same genuine transaction. Existing completed history is never backfilled.
WITH root AS MATERIALIZED (
 SELECT id,org_id,status FROM documents WHERE id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid FOR UPDATE NOWAIT
), candidate AS MATERIALIZED (
 SELECT a.attempt_id,a.org_id,a.document_id,root.status AS outcome,a.manifest_sha256,a.legal_commitment_sha256,a.article13_notice_epoch_at,a.retain_until,
  (SELECT count(*)::integer FROM recipients WHERE document_id=a.document_id) AS recipient_count,
  (SELECT count(*)::integer FROM document_package_send_initial_invite_receipts_v1 WHERE attempt_id=a.attempt_id) AS invite_count,
  hash_package_send_event_id_v1(a.attempt_id,'document.sent',NULL) AS sent_event_id,
  CASE WHEN root.status='expired' THEN hash_package_send_event_id_v1(a.attempt_id,'document.expired',NULL) END AS expired_event_id
 FROM root JOIN document_package_send_attempts_v1 a ON a.document_id=root.id AND a.org_id=root.org_id
 WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.terminal_outcome IS NULL AND root.status IN ('sent','expired')
  AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
  AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
  AND hash_package_send_completion_version_v1()=1
)
INSERT INTO document_package_send_completions_v1(attempt_id,org_id,document_id,outcome,manifest_sha256,legal_commitment_sha256,article13_notice_epoch_at,retain_until,
 recipient_count,invite_count,sent_event_id,sent_event_row_sha256,expired_event_id,expired_event_row_sha256,effect_sha256)
SELECT c.attempt_id,c.org_id,c.document_id,c.outcome,c.manifest_sha256,c.legal_commitment_sha256,c.article13_notice_epoch_at,c.retain_until,c.recipient_count,c.invite_count,
 c.sent_event_id,se.row_hash,c.expired_event_id,ee.row_hash,
 hash_package_send_completion_effect_v1(c.attempt_id,c.outcome,c.recipient_count,c.invite_count,c.sent_event_id,c.expired_event_id)
FROM candidate c JOIN events se ON se.id=c.sent_event_id LEFT JOIN events ee ON ee.id=c.expired_event_id
WHERE c.recipient_count>=0 AND c.invite_count>=0
RETURNING *;

-- name: InspectDocumentPackageSendCompletionV1 :one
-- Historical scalar proof is independent of later token rotation, recipient or
-- mail cleanup, mutable document status and event display-payload redaction.
SELECT c.* FROM document_package_send_completions_v1 c
JOIN document_package_send_attempts_v1 a ON a.attempt_id=c.attempt_id AND a.org_id=c.org_id AND a.document_id=c.document_id
WHERE c.attempt_id=sqlc.arg(attempt_id)::uuid AND c.org_id=sqlc.arg(org_id)::uuid AND c.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
 AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome='completed' AND hash_package_send_completion_version_v1()=1;
