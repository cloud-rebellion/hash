-- name: InsertAICompletionAudit :one
INSERT INTO ai_completion_audit (
    org_id, document_id, actor_user_id, provider, model,
    prompt_name, prompt_version, shield_active,
    input_tokens, output_tokens, latency_ms, success, error,
    transfer_jurisdiction
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8,
    $9, $10, $11, $12, $13,
    $14
) RETURNING *;

-- name: GetOrgAISettings :one
SELECT * FROM org_ai_settings WHERE org_id = $1;

-- name: UpsertOrgAISettings :one
INSERT INTO org_ai_settings (
    org_id, provider, base_url, model, api_key_ct, key_last4, enabled, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, now()
)
ON CONFLICT (org_id) DO UPDATE SET
    provider   = EXCLUDED.provider,
    base_url   = EXCLUDED.base_url,
    model      = EXCLUDED.model,
    api_key_ct = EXCLUDED.api_key_ct,
    key_last4  = EXCLUDED.key_last4,
    enabled    = EXCLUDED.enabled,
    updated_at = now()
RETURNING *;

-- name: DeleteOrgAISettings :exec
DELETE FROM org_ai_settings WHERE org_id = $1;


-- name: InsertRequestedAICompletionAudit :one
-- Exactly one provider completion belongs to an authorized durable request.
-- Reusing the immutable request event UUID links cost even if result delivery
-- later fails. A missing/foreign/mismatched receipt and a duplicate completion
-- produce no row, so callers must refuse delivery.
INSERT INTO ai_completion_audit (
    id, org_id, document_id, actor_user_id, provider, model,
    prompt_name, prompt_version, shield_active,
    input_tokens, output_tokens, latency_ms, success, error,
    transfer_jurisdiction
)
SELECT sqlc.arg(request_event_id)::uuid, sqlc.arg(org_id)::uuid,
       sqlc.arg(document_id)::uuid, sqlc.arg(actor_user_id)::uuid,
       sqlc.arg(provider)::text, sqlc.arg(model)::text,
       sqlc.arg(prompt_name)::text, sqlc.arg(prompt_version)::int,
       sqlc.arg(shield_active)::boolean,
       sqlc.arg(input_tokens)::int, sqlc.arg(output_tokens)::int,
       sqlc.arg(latency_ms)::int, sqlc.arg(success)::boolean,
       sqlc.arg(error)::text, sqlc.arg(transfer_jurisdiction)::text
WHERE EXISTS (
    SELECT 1 FROM events
    WHERE id = sqlc.arg(request_event_id)::uuid
      AND org_id = sqlc.arg(org_id)::uuid
      AND document_id = sqlc.arg(document_id)::uuid
      AND actor_user_id = sqlc.arg(actor_user_id)::uuid
      AND kind = 'ai.requested'
)
ON CONFLICT (id) DO NOTHING
RETURNING *;

-- name: InsertRequestedSignerAICompletionAudit :one
-- Signer processing is attributed to its immutable recipient-bound request,
-- never to the sender's staff user. Reuse the event UUID to prevent duplicates.
INSERT INTO ai_completion_audit (
    id, org_id, document_id, actor_user_id, provider, model,
    prompt_name, prompt_version, shield_active,
    input_tokens, output_tokens, latency_ms, success, error,
    transfer_jurisdiction
)
SELECT sqlc.arg(request_event_id)::uuid, sqlc.arg(org_id)::uuid,
       sqlc.arg(document_id)::uuid, NULL,
       sqlc.arg(provider)::text, sqlc.arg(model)::text,
       sqlc.arg(prompt_name)::text, sqlc.arg(prompt_version)::int,
       sqlc.arg(shield_active)::boolean,
       sqlc.arg(input_tokens)::int, sqlc.arg(output_tokens)::int,
       sqlc.arg(latency_ms)::int, sqlc.arg(success)::boolean,
       sqlc.arg(error)::text, sqlc.arg(transfer_jurisdiction)::text
WHERE EXISTS (
    SELECT 1 FROM events
    WHERE id = sqlc.arg(request_event_id)::uuid
      AND org_id = sqlc.arg(org_id)::uuid
      AND document_id = sqlc.arg(document_id)::uuid
      AND recipient_id = sqlc.arg(recipient_id)::uuid
      AND actor_user_id IS NULL
      AND kind = 'ai.requested'
)
ON CONFLICT (id) DO NOTHING
RETURNING *;
