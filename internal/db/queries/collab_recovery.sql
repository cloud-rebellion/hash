-- name: ListCollabRecoveryArchives :many
SELECT a.id, a.origin, a.history_generation, a.observed_canonical_generation,
       a.created_at, a.expires_at, octet_length(a.ydoc_state)::integer AS size_bytes
FROM collab_recovery_archives a JOIN documents d ON d.id = a.document_id
WHERE d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
ORDER BY a.created_at, a.id LIMIT 16;

-- name: GetCollabRecoveryArchive :one
SELECT a.* FROM collab_recovery_archives a JOIN documents d ON d.id = a.document_id
WHERE a.id = sqlc.arg(archive_id)::uuid AND d.id = sqlc.arg(document_id)::uuid
  AND d.org_id = sqlc.arg(org_id)::uuid;

-- name: DeleteCollabRecoveryArchive :execrows
DELETE FROM collab_recovery_archives a USING documents d
WHERE a.id = sqlc.arg(archive_id)::uuid AND d.id = a.document_id
  AND d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid;

-- name: CollabArchiveDeletionDeferred :one
SELECT EXISTS(SELECT 1 FROM data_subject_requests
WHERE (document_id = sqlc.arg(document_id)::uuid OR document_id IS NULL) AND org_id = sqlc.arg(org_id)::uuid
  AND status IN ('open','in_progress') AND kind IN ('access','portability','restriction')) AS deferred;

-- name: TryCollabArchivePrivacyFence :one
SELECT pg_try_advisory_xact_lock_shared(hash_collab_archive_dsr_lock_key(sqlc.arg(org_id)::uuid))::boolean AS acquired;

-- name: PurgeExpiredCollabRecoveryArchives :one
SELECT hash_purge_expired_collab_archives()::bigint AS deleted;
