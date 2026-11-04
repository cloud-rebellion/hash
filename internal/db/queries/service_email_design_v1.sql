-- name: GetServiceEmailAIProviderHeaderV1 :one
-- Original owner transaction holds this exact workspace provider before the
-- bounded ciphertext/source read. No document identity is fabricated.
SELECT org_id,enabled,updated_at,created_at,
 octet_length(provider)::bigint AS provider_bytes,
 octet_length(base_url)::bigint AS base_url_bytes,
 octet_length(model)::bigint AS model_bytes,
 octet_length(api_key_ct)::bigint AS key_bytes,
 octet_length(key_last4)::bigint AS key_last4_bytes
FROM org_ai_settings WHERE org_id=$1 FOR SHARE;
