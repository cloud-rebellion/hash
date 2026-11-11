-- name: GetOrgEmailPreferencesV1 :one
SELECT org_id,revision,locale,updated_at
FROM org_email_preferences_v1
WHERE org_id=$1
FOR SHARE;

-- name: CreateOrgEmailPreferencesV1 :one
INSERT INTO org_email_preferences_v1(org_id,revision,locale)
VALUES(sqlc.arg(org_id),1,sqlc.arg(locale))
ON CONFLICT(org_id) DO NOTHING
RETURNING org_id,revision,locale,updated_at;

-- name: UpdateOrgEmailPreferencesV1 :one
UPDATE org_email_preferences_v1
SET revision=revision+1,locale=sqlc.arg(locale),updated_at=clock_timestamp()
WHERE org_id=sqlc.arg(org_id) AND revision=sqlc.arg(expected_revision)::bigint
RETURNING org_id,revision,locale,updated_at;
