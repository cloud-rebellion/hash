-- name: GetCollabDocState :one
SELECT * FROM collab_doc_states WHERE document_id = $1;

-- name: UpsertCollabDocState :one
INSERT INTO collab_doc_states (
    document_id, ydoc_state, state_size, update_count, last_user_id
) VALUES (
    $1, $2, $3, $4, $5
)
ON CONFLICT (document_id) DO UPDATE SET
    ydoc_state   = EXCLUDED.ydoc_state,
    state_size   = EXCLUDED.state_size,
    update_count = collab_doc_states.update_count + EXCLUDED.update_count,
    last_user_id = COALESCE(EXCLUDED.last_user_id, collab_doc_states.last_user_id),
    updated_at   = now()
RETURNING *;

-- name: GetDocumentCollabGeneration :one
SELECT g.generation FROM collab_document_generations g
JOIN documents d ON d.id = g.document_id
WHERE d.id = $1 AND d.org_id = $2;

-- name: GetCollabDocStateWithGeneration :one
-- Null generation denotes legacy state with no established canonical association.
SELECT s.*, g.generation FROM collab_doc_states s
LEFT JOIN collab_state_generations g USING (document_id)
WHERE s.document_id = $1;

-- name: PersistCollabDocStateForGeneration :one
SELECT hash_persist_collab_generation(
    sqlc.arg(document_id)::uuid, sqlc.arg(org_id)::uuid,
    sqlc.arg(generation)::bigint, sqlc.arg(ydoc_state)::bytea,
    sqlc.arg(state_size)::integer, sqlc.arg(update_count)::integer,
    sqlc.narg(last_user_id)::uuid
)::boolean AS accepted;

-- name: SaveCanonicalCollab :one
SELECT hash_save_canonical_collab(
    sqlc.arg(document_id)::uuid, sqlc.arg(org_id)::uuid,
    sqlc.arg(generation)::bigint, sqlc.arg(expected_updated_at)::timestamptz,
    sqlc.arg(blocks_json)::jsonb, sqlc.narg(variables_json)::jsonb,
    sqlc.arg(ydoc_state)::bytea, sqlc.arg(update_count)::integer,
    sqlc.arg(user_id)::uuid
)::boolean AS accepted;

-- name: RecoverCanonicalCollab :one
SELECT hash_recover_canonical_collab(
    sqlc.arg(document_id)::uuid, sqlc.arg(org_id)::uuid,
    sqlc.arg(generation)::bigint, sqlc.arg(expected_updated_at)::timestamptz,
    sqlc.arg(user_id)::uuid, sqlc.arg(acknowledged)::boolean,
    sqlc.narg(room_state)::bytea, sqlc.narg(room_generation)::bigint
)::bigint AS generation;
