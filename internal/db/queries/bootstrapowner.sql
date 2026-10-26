-- name: CreateBootstrapOwnerOrg :one
-- Only the explicit first-owner maintenance command uses a planned organization
-- identity. Normal registration keeps its database-generated identity.
INSERT INTO orgs (id, name, plan)
VALUES ($1, $2, $3)
RETURNING *;
