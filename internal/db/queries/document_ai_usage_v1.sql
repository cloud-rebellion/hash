-- name: PersistDocumentAIUsageV1 :execrows
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
;
