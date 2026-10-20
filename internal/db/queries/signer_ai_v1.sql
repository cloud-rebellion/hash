-- name: PersistSignerAIUsageV1 :execrows
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
      AND actor_user_id IS NULL
      AND recipient_id = sqlc.arg(recipient_id)::uuid
      AND kind = 'ai.requested'
)
ON CONFLICT (id) DO NOTHING
;


-- name: GetSignerAIUsageHeaderV1 :one
SELECT a.id,a.org_id,a.document_id,a.actor_user_id,a.created_at,
 (octet_length(a.provider)::numeric+octet_length(a.model)+octet_length(a.prompt_name)
 +octet_length(a.error)+octet_length(a.transfer_jurisdiction))::bigint AS raw_text_bytes
FROM ai_completion_audit a
WHERE a.id=sqlc.arg(request_event_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid
 AND a.document_id=sqlc.arg(document_id)::uuid AND a.actor_user_id IS NULL
 AND EXISTS(SELECT 1 FROM events e WHERE e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id IS NULL AND e.recipient_id=sqlc.arg(recipient_id)::uuid AND e.kind='ai.requested')
FOR SHARE OF a;

-- name: ReadSignerAIUsageV1 :one
SELECT a.* FROM ai_completion_audit a
WHERE a.id=sqlc.arg(request_event_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid
 AND a.document_id=sqlc.arg(document_id)::uuid AND a.actor_user_id IS NULL
 AND EXISTS(SELECT 1 FROM events e WHERE e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id IS NULL AND e.recipient_id=sqlc.arg(recipient_id)::uuid AND e.kind='ai.requested')
 AND a.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND (octet_length(a.provider)::numeric+octet_length(a.model)+octet_length(a.prompt_name)
 +octet_length(a.error)+octet_length(a.transfer_jurisdiction))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: GetSignerAICredentialPinsV1 :one
-- Root then logical document and recipient SHARE are already owned. Only real
-- scalar facts/comparisons leave PostgreSQL; no source JSON/text body expands.
SELECT d.sent_at,d.article13_notice_epoch_at,d.article13_notice_epoch_v61_committed,
 d.expires_at,r.magic_token_expires_at,
 COALESCE(d.name=sqlc.arg(original_name)::text,false)::boolean AS name_matches,
 COALESCE(d.lawful_basis=sqlc.arg(original_basis)::text,false)::boolean AS basis_matches,
 COALESCE(d.article13_notice_schema=sqlc.arg(original_schema)::text,false)::boolean AS schema_matches,
 COALESCE(r.role=sqlc.arg(original_role)::text,false)::boolean AS role_matches
FROM documents d JOIN recipients r ON r.document_id=d.id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND r.id=sqlc.arg(recipient_id)::uuid AND d.deleted_at IS NULL
 AND octet_length(r.magic_token_hash)=32 AND r.magic_token_hash=sqlc.arg(token_hash)::bytea;
