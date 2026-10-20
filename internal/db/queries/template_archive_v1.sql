-- name: ArchiveNativeTemplateIdentityV1 :one
UPDATE templates
SET archived_at=now(),updated_at=now()
WHERE id=sqlc.arg(template_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND archived_at IS NULL AND version=sqlc.arg(expected_version)::integer AND updated_at=sqlc.arg(expected_updated_at)::timestamptz
RETURNING id,org_id,version,archived_at,updated_at;
