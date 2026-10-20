-- Read-only recipient package projection. Scope is derived only from the genuine
-- token reader and the current root epoch, never a caller package/revision.
-- name: HasSignerPackageReadHistoryV1 :one
-- Older terminal attempts belong to their own epochs. Missing authority for
-- the current epoch or any unresolved attempt must never become legacy absence.
SELECT (EXISTS(SELECT 1 FROM document_package_send_attempts_v1 a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
 WHERE a.document_id=sqlc.arg(document_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid
 AND (a.terminal_outcome IS NULL OR a.article13_notice_epoch_at=d.article13_notice_epoch_at))
 OR EXISTS(SELECT 1 FROM document_package_send_completions_v1 c JOIN documents d ON d.id=c.document_id AND d.org_id=c.org_id
 WHERE c.document_id=sqlc.arg(document_id)::uuid AND c.org_id=sqlc.arg(org_id)::uuid AND c.article13_notice_epoch_at=d.article13_notice_epoch_at)
 OR EXISTS(SELECT 1 FROM document_package_send_initial_invite_receipts_v1 i JOIN documents d ON d.id=i.document_id AND d.org_id=i.org_id
 LEFT JOIN document_package_send_attempts_v1 a ON a.attempt_id=i.attempt_id AND a.document_id=i.document_id AND a.org_id=i.org_id
 WHERE i.document_id=sqlc.arg(document_id)::uuid AND i.org_id=sqlc.arg(org_id)::uuid
 AND (a.attempt_id IS NULL OR a.terminal_outcome IS NULL OR a.article13_notice_epoch_at=d.article13_notice_epoch_at)))::boolean;

-- name: ListSignerPackageReadBindingV1 :many
-- Limit2 detects ambiguity; no latest/head selection may adopt another capture.
SELECT a.attempt_id,a.package_id
FROM documents d JOIN recipients r ON r.document_id=d.id
JOIN document_package_send_attempts_v1 a ON a.document_id=d.id AND a.org_id=d.org_id
JOIN document_package_send_completions_v1 c ON c.attempt_id=a.attempt_id AND c.document_id=a.document_id AND c.org_id=a.org_id
JOIN document_package_send_initial_invite_receipts_v1 i ON i.attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id AND i.recipient_id=r.id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND r.id=sqlc.arg(recipient_id)::uuid AND r.magic_token_hash=sqlc.arg(token_hash)::bytea
 AND d.status IN ('sent','in_progress','changes_requested') AND d.source_kind='pdf' AND NOT d.is_envelope AND d.parent_envelope_id IS NULL
 AND d.sent_at=a.article13_notice_epoch_at AND d.article13_notice_epoch_at=a.article13_notice_epoch_at AND d.article13_notice_epoch_v61_committed
 AND a.terminal_outcome='completed' AND a.retention_started_at IS NOT NULL AND a.retention_completed_at IS NOT NULL
 AND c.outcome='sent' AND c.article13_notice_epoch_at=a.article13_notice_epoch_at AND c.retain_until=a.retain_until
 AND c.manifest_sha256=a.manifest_sha256 AND c.legal_commitment_sha256=a.legal_commitment_sha256
 AND hash_package_send_completion_version_v1()=1
 AND hash_package_send_main_matches_v1(d.id,d.org_id,a.package_id,a.capture_revision)
ORDER BY a.attempt_id LIMIT 2;
