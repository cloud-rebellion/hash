-- name: ListPresignApprovedTemplateDescriptors :many
SELECT t.name, r.template_id, r.org_id, r.version, r.content_sha256,
       r.approved_by, r.approved_at,
       (octet_length(r.html_master_json::text)::bigint + octet_length(r.variables_json::text)::bigint)::bigint AS source_bytes
FROM html_template_revisions r
JOIN templates t ON t.id = r.template_id AND t.org_id = r.org_id
WHERE r.org_id = $1::uuid AND t.source_kind = 'html' AND t.archived_at IS NULL
  AND r.approved_by IS NOT NULL AND r.approved_at IS NOT NULL
  AND r.html_master_json->>'schema_version' = '3'
ORDER BY r.approved_at DESC, r.template_id, r.version DESC
LIMIT 21;
