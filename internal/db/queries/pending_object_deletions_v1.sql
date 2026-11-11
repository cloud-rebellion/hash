-- name: InsertPendingObjectDeletionV1 :one
-- Written in the erasure's own transaction. The first attempt belongs to the
-- request handler, so the sweep is held off for a grace period; a crashed
-- request leaves the row for the sweep once that period ends. Re-inserting the
-- same version keeps the earlier row.
INSERT INTO pending_object_deletions_v1 (id, org_id, document_id, dsr_id, storage_key, version_id, sha256, next_attempt_at)
VALUES (sqlc.arg(id), sqlc.arg(org_id), sqlc.arg(document_id), sqlc.narg(dsr_id), sqlc.arg(storage_key), sqlc.arg(version_id), sqlc.arg(sha256),
        clock_timestamp() + make_interval(secs => sqlc.arg(grace_seconds)::double precision))
ON CONFLICT (org_id, storage_key, version_id) DO UPDATE SET document_id = pending_object_deletions_v1.document_id
RETURNING *;

-- name: ClaimDuePendingObjectDeletionsV1 :many
-- Lease a bounded batch for the sweep. The lease is the push of next_attempt_at:
-- peers skip a leased row, and a crashed sweep leaves it eligible again.
WITH due AS (
  SELECT id FROM pending_object_deletions_v1
  WHERE next_attempt_at <= clock_timestamp()
  ORDER BY next_attempt_at, id
  FOR UPDATE SKIP LOCKED
  LIMIT sqlc.arg(batch_limit)
)
UPDATE pending_object_deletions_v1 p
SET next_attempt_at = clock_timestamp() + make_interval(secs => sqlc.arg(lease_seconds)::double precision)
FROM due
WHERE p.id = due.id
RETURNING p.*;

-- name: DeletePendingObjectDeletionV1 :execrows
-- Only after the object store confirmed the exact version is gone.
DELETE FROM pending_object_deletions_v1
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id);

-- name: RecordPendingObjectDeletionFailureV1 :execrows
UPDATE pending_object_deletions_v1
SET attempts = attempts + 1,
    last_error = sqlc.arg(last_error),
    next_attempt_at = clock_timestamp() + make_interval(secs => sqlc.arg(backoff_seconds)::double precision)
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id);

-- name: ListPendingObjectDeletionsForDocumentV1 :many
SELECT * FROM pending_object_deletions_v1
WHERE org_id = sqlc.arg(org_id) AND document_id = sqlc.arg(document_id)
ORDER BY created_at, id;

-- name: LockDSRErasureFulfilmentV1 :exec
-- Serializes erasure fulfilment per organization. Two erasures for the same
-- subject, linked to different documents, otherwise lock their linked document
-- first and the shared fan-out set second, and deadlock. The key is private to
-- this statement; nothing else takes it, so it cannot join a lock cycle.
SELECT pg_advisory_xact_lock(hashtextextended('hash-dsr-erasure:' || sqlc.arg(org_id)::text, 0));

-- name: DSRSubjectEmailMatchesRecipientV1 :one
-- The comparison the history scope query uses (ListPDFRevisionDocumentsForSubject):
-- lower(btrim(..)) on both sides, in the database, so it cannot drift from it.
SELECT (lower(btrim(sqlc.arg(subject_email)::text)) = lower(btrim(sqlc.arg(recipient_email)::text)))::boolean AS matches;
