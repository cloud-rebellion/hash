-- name: ListNativeTemplatePageHeadersV1 :many
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,(octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint AS raw_text_bytes
 FROM templates t WHERE t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL
 ORDER BY t.updated_at DESC LIMIT sqlc.arg(page_limit)::integer OFFSET sqlc.arg(page_offset)::integer FOR SHARE OF t
), nonhtml AS MATERIALIZED (
 SELECT m.* FROM pdf_template_source_sizes_v1 m JOIN parent p ON p.id=m.template_id AND p.org_id=m.org_id
 AND p.source_kind IN ('pdf','blocks') AND p.source_kind=m.source_kind AND p.version=m.template_version
 AND p.created_at=m.template_created_at AND p.updated_at=m.template_updated_at FOR SHARE OF m
), html AS MATERIALIZED (
 SELECT m.* FROM html_authoring_template_sizes_v1 m JOIN parent p ON p.id=m.template_id AND p.org_id=m.org_id AND p.source_kind='html' FOR SHARE OF m
)
SELECT p.id,p.org_id,p.source_kind,p.version,p.created_at,p.updated_at,p.raw_text_bytes,
 CASE WHEN p.source_kind='html' THEN COALESCE(h.master_wire_bytes,-1::bigint) ELSE COALESCE(n.master_wire_bytes,-1::bigint) END::bigint AS master_wire_bytes,
 CASE WHEN p.source_kind='html' THEN COALESCE(h.variables_wire_bytes,-1::bigint) ELSE COALESCE(n.variables_wire_bytes,-1::bigint) END::bigint AS variables_wire_bytes,
 CASE WHEN p.source_kind='html' THEN COALESCE(h.blocks_wire_bytes,-1::bigint) ELSE COALESCE(n.blocks_wire_bytes,-1::bigint) END::bigint AS blocks_wire_bytes,
 CASE WHEN p.source_kind='html' THEN COALESCE(h.fields_wire_bytes,-1::bigint) ELSE COALESCE(n.fields_wire_bytes,-1::bigint) END::bigint AS fields_wire_bytes,
 CASE WHEN p.source_kind='html' THEN COALESCE(h.sanitization_wire_bytes,-1::bigint) ELSE COALESCE(n.sanitization_wire_bytes,-1::bigint) END::bigint AS sanitization_wire_bytes,
 CASE WHEN p.source_kind='html' THEN COALESCE(h.measurement_server_version_num,-1::integer) ELSE COALESCE(n.measurement_server_version_num,-1::integer) END::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent p LEFT JOIN nonhtml n ON n.template_id=p.id AND n.org_id=p.org_id LEFT JOIN html h ON h.template_id=p.id AND h.org_id=p.org_id
ORDER BY p.updated_at DESC;

-- name: ReadNativeTemplateListProjectionV1 :many
-- Arrays originate only from the SAME native protected header page. Actual
-- parent/cache locks remain held; source-kind/pins and actual projected byte
-- lengths are checked again before any source-bearing model is transferred.
SELECT t.id,t.org_id,t.name,t.source_kind,t.blocks_json,t.variables_json,
 t.pdf_storage_key,t.pdf_sha256,t.page_count,t.fields_json,t.version,t.created_by,t.created_at,t.updated_at,t.archived_at,
 t.pdf_storage_version_id,t.evidence_version_pin_required,NULL::jsonb AS html_master_json,t.html_content_sha256,NULL::jsonb AS pdf_sanitization_report
FROM unnest(sqlc.arg(template_ids)::uuid[]) WITH ORDINALITY AS p(id,ordinal)
JOIN templates t ON t.id=p.id AND t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL
 AND t.version=(sqlc.arg(expected_versions)::integer[])[p.ordinal::integer]
 AND t.created_at=(sqlc.arg(expected_created_ats)::timestamptz[])[p.ordinal::integer]
 AND t.updated_at=(sqlc.arg(expected_updated_ats)::timestamptz[])[p.ordinal::integer]
 AND t.source_kind=(sqlc.arg(expected_source_kinds)::text[])[p.ordinal::integer]
WHERE (octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint=(sqlc.arg(expected_raw_text_bytes)::bigint[])[p.ordinal::integer]
 AND COALESCE(octet_length(t.blocks_json::text),0)::bigint=(sqlc.arg(expected_blocks_wire_bytes)::bigint[])[p.ordinal::integer]
 AND octet_length(t.variables_json::text)::bigint=(sqlc.arg(expected_variables_wire_bytes)::bigint[])[p.ordinal::integer]
 AND octet_length(t.fields_json::text)::bigint=(sqlc.arg(expected_fields_wire_bytes)::bigint[])[p.ordinal::integer]
ORDER BY p.ordinal;
