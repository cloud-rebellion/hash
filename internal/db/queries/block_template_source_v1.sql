-- name: CreateFreshBlocksTemplateSourceV1 :one
INSERT INTO templates (id, org_id, name, source_kind, blocks_json, variables_json, created_by)
VALUES (sqlc.arg(id)::uuid, sqlc.arg(org_id)::uuid, sqlc.arg(name)::text, 'blocks', sqlc.arg(blocks_json)::jsonb, sqlc.arg(variables_json)::jsonb, sqlc.arg(created_by)::uuid)
RETURNING *;
