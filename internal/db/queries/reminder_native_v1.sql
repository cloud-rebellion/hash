-- SOURCE ONLY. Identity is an unlocked scoped hint; mutation must recheck it
-- under the actual root-first native family locks before any reminder effect.
-- name: ResolveReminderRootIdentityV1 :one
SELECT subject.id AS document_id,subject.org_id,root.id AS root_document_id
FROM documents subject JOIN documents root
 ON root.id=COALESCE(subject.parent_envelope_id,subject.id)
 AND root.org_id=subject.org_id AND root.parent_envelope_id IS NULL
WHERE subject.id=sqlc.arg(document_id)::uuid AND subject.org_id=sqlc.arg(org_id)::uuid
 AND subject.deleted_at IS NULL AND root.deleted_at IS NULL;

-- name: GetReminderScheduleHeaderV1 :one
SELECT r.document_id,r.next_fire_at,r.last_fired_at,r.fires_remaining,
 octet_length(r.schedule_json::text)::bigint AS schedule_wire_bytes
FROM reminders r JOIN documents d ON d.id=r.document_id
WHERE r.document_id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND d.status IN ('sent','in_progress')
FOR UPDATE OF r;

-- Only after the scalar wire/body/parse loan, on the SAME original schedule lock.
-- name: ReadReminderScheduleV1 :one
SELECT r.* FROM reminders r JOIN documents d ON d.id=r.document_id
WHERE r.document_id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND d.status IN ('sent','in_progress')
 AND octet_length(r.schedule_json::text)=sqlc.arg(expected_wire_bytes)::bigint;

-- name: RotateReminderRecipientV1 :one
UPDATE recipients r SET magic_token_hash=sqlc.arg(token_hash)::bytea,
 magic_token_expires_at=sqlc.arg(token_expires_at)::timestamptz
FROM documents d WHERE d.id=r.document_id AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.id=sqlc.arg(document_id)::uuid AND d.deleted_at IS NULL
 AND d.status IN ('sent','in_progress') AND r.id=sqlc.arg(recipient_id)::uuid
 AND r.status IN ('pending','sent','viewed')
 AND r.magic_token_hash IS NOT DISTINCT FROM sqlc.narg(expected_token_hash)::bytea
RETURNING r.*;

-- name: AdvanceNativeReminderV1 :one
UPDATE reminders SET last_fired_at=now(),next_fire_at=sqlc.arg(next_fire_at)::timestamptz,
 fires_remaining=fires_remaining-1
WHERE document_id=sqlc.arg(document_id)::uuid
 AND fires_remaining=sqlc.arg(expected_fires_remaining)::integer
RETURNING *;
