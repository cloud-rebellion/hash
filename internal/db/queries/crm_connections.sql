-- name: GetCRMConnectionByOrg :one
SELECT * FROM crm_connections WHERE org_id = $1;

-- name: GetCRMConnectionByOrgForShare :one
SELECT * FROM crm_connections WHERE org_id = $1 FOR SHARE;

-- name: SaveCRMConnectionCandidate :one
INSERT INTO crm_connections (org_id, id, generation, status, origin, crm_team_id, crm_user_id, credential_ciphertext, verified_at)
SELECT sqlc.arg(org_id)::uuid, sqlc.arg(id)::uuid, sqlc.arg(generation)::bigint, 'candidate',
       sqlc.arg(origin)::text, sqlc.arg(crm_team_id)::text, sqlc.arg(crm_user_id)::text,
       sqlc.arg(credential_ciphertext)::bytea, sqlc.arg(verified_at)::timestamptz
WHERE sqlc.arg(expected_generation)::bigint = 0 OR EXISTS (
    SELECT 1 FROM crm_connections c WHERE c.org_id = sqlc.arg(org_id)
        AND c.generation = sqlc.arg(expected_generation) AND c.id = sqlc.arg(id))
ON CONFLICT (org_id) DO UPDATE SET
    generation = EXCLUDED.generation, status = 'candidate', origin = EXCLUDED.origin,
    crm_team_id = EXCLUDED.crm_team_id, crm_user_id = EXCLUDED.crm_user_id,
    credential_ciphertext = EXCLUDED.credential_ciphertext, verified_at = EXCLUDED.verified_at,
    updated_at = clock_timestamp()
WHERE crm_connections.generation = sqlc.arg(expected_generation)
  AND crm_connections.id = EXCLUDED.id
RETURNING *;

-- name: EnableCRMConnection :one
UPDATE crm_connections SET generation = sqlc.arg(generation), status = 'active',
    credential_ciphertext = sqlc.arg(credential_ciphertext), verified_at = sqlc.arg(verified_at),
    updated_at = clock_timestamp()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND generation = sqlc.arg(expected_generation)
    AND status = 'candidate' AND origin = sqlc.arg(origin)
    AND crm_team_id = sqlc.arg(crm_team_id) AND crm_user_id = sqlc.arg(crm_user_id)
RETURNING *;

-- name: RevokeCRMConnection :one
UPDATE crm_connections SET generation = generation + 1, status = 'revoked',
    credential_ciphertext = NULL, updated_at = clock_timestamp()
WHERE org_id = sqlc.arg(org_id) AND generation = sqlc.arg(expected_generation)
    AND generation < 9223372036854775807 AND status <> 'revoked'
RETURNING *;
