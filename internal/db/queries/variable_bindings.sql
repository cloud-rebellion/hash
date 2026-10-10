-- name: UpsertVariableBinding :one
INSERT INTO document_variable_bindings (
    document_id, variable_name, source_kind, source_ref, source_path, fallback
)
SELECT d.id, sqlc.arg(variable_name)::text, sqlc.arg(source_kind)::text,
       sqlc.arg(source_ref)::text, sqlc.arg(source_path)::text, sqlc.arg(fallback)::text
FROM documents d
WHERE d.id = sqlc.arg(document_id) AND d.status = 'draft' AND d.deleted_at IS NULL
ON CONFLICT (document_id, variable_name) DO UPDATE SET
    source_kind = EXCLUDED.source_kind,
    source_ref  = EXCLUDED.source_ref,
    source_path = EXCLUDED.source_path,
    fallback    = EXCLUDED.fallback,
    updated_at  = now()
RETURNING *;

-- name: ListVariableBindings :many
SELECT * FROM document_variable_bindings
WHERE document_id = $1
ORDER BY variable_name ASC;

-- name: ListOrgIDsForVariableSource :many
-- Resolve an inbound integration event to the tenant ledgers it affects. The
-- webhook handler audits once per matching org before invalidating its
-- process-local resolver cache; a zero-org result is a genuine no-op.
SELECT DISTINCT d.org_id
FROM document_variable_bindings AS b
JOIN documents AS d ON d.id = b.document_id
WHERE b.source_kind = $1
  AND b.source_ref = $2
  -- Only draft documents ever fetch live bindings. Sent/final/deleted rows use
  -- their frozen values and must not cause indefinite inbound audit traffic.
  AND d.status = 'draft'
  AND d.deleted_at IS NULL
ORDER BY d.org_id;

-- name: PurgeExpiredBrightCRMWebhookReceipts :execrows
-- Opportunistically bound the replay inbox without letting one request spend
-- unbounded time deleting a long-neglected backlog.
WITH expired AS (
    SELECT delivery_correlation
    FROM brightcrm_webhook_receipts
    WHERE expires_at <= now()
    ORDER BY expires_at, delivery_correlation
    LIMIT 1000
    FOR UPDATE SKIP LOCKED
)
DELETE FROM brightcrm_webhook_receipts AS receipts
USING expired
WHERE receipts.delivery_correlation = expired.delivery_correlation;

-- name: ClaimBrightCRMWebhookReceipt :execrows
INSERT INTO brightcrm_webhook_receipts (
    delivery_correlation, payload_correlation, org_ids
) VALUES (
    sqlc.arg(delivery_correlation), sqlc.arg(payload_correlation), sqlc.arg(org_ids)
)
ON CONFLICT (delivery_correlation) DO NOTHING;

-- name: GetBrightCRMWebhookReceipt :one
SELECT payload_correlation, org_ids
FROM brightcrm_webhook_receipts
WHERE delivery_correlation = $1;

-- name: DeleteVariableBinding :exec
DELETE FROM document_variable_bindings
WHERE document_id = $1 AND variable_name = $2
  AND EXISTS (SELECT 1 FROM documents d
      WHERE d.id = document_variable_bindings.document_id
        AND d.status = 'draft' AND d.deleted_at IS NULL);

-- name: GetResolverDocumentRevisionForShare :one
SELECT id, org_id, status, updated_at
FROM documents
WHERE id = sqlc.arg(document_id) AND org_id = sqlc.arg(org_id) AND deleted_at IS NULL
FOR SHARE;

-- name: ListVariableBindingsForShare :many
SELECT * FROM document_variable_bindings
WHERE document_id = $1
ORDER BY variable_name ASC
FOR SHARE;

-- name: UpdateVariableBindingResolved :execrows
-- Observations are admitted only by the reviewed send transaction after member,
-- credential and family locks. Match both revisions; never overwrite a binding
-- that was edited/deleted/recreated while its upstream request was in flight.
UPDATE document_variable_bindings b
   SET last_value = sqlc.arg(last_value), last_resolved = clock_timestamp(),
       last_error = '', updated_at = clock_timestamp()
 WHERE b.document_id = sqlc.arg(document_id) AND b.variable_name = sqlc.arg(variable_name)
   AND b.created_at = sqlc.arg(expected_binding_created_at)
   AND b.updated_at = sqlc.arg(expected_binding_updated_at)
   AND EXISTS (SELECT 1 FROM documents d WHERE d.id = b.document_id
       AND d.org_id = sqlc.arg(org_id) AND d.status = 'draft' AND d.deleted_at IS NULL
       AND d.updated_at = sqlc.arg(expected_document_updated_at));

-- name: UpdateVariableBindingError :execrows
UPDATE document_variable_bindings b
   SET last_error = sqlc.arg(last_error), last_resolved = clock_timestamp(),
       updated_at = clock_timestamp()
 WHERE b.document_id = sqlc.arg(document_id) AND b.variable_name = sqlc.arg(variable_name)
   AND b.created_at = sqlc.arg(expected_binding_created_at)
   AND b.updated_at = sqlc.arg(expected_binding_updated_at)
   AND EXISTS (SELECT 1 FROM documents d WHERE d.id = b.document_id
       AND d.org_id = sqlc.arg(org_id) AND d.status = 'draft' AND d.deleted_at IS NULL
       AND d.updated_at = sqlc.arg(expected_document_updated_at));
