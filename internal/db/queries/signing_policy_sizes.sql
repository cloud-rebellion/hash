-- SOURCE-ONLY QUERY CONTRACT. Requires installed protected size caches.
-- Real header loan and SAME owned READ COMMITTED parent->ordered parties->88
-- locks precede this query. Explicit field->branding->cache locks are consumed
-- before TEXT-length aggregates; never measure or expand JSONB in this header.
-- name: GetSignatureFitHTMLPolicySizeHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.signing_admission_active_id,
  (d.html_source_json IS NOT NULL)::boolean AS has_html_source,
  (d.html_current_source_json IS NOT NULL)::boolean AS has_current_html_source,
  (octet_length(d.name)::numeric+octet_length(d.status)+octet_length(d.source_kind)
   +octet_length(d.routing_tier)+octet_length(d.routing_mode)+octet_length(d.lawful_basis)+octet_length(d.signing_admission_policy)
   +octet_length(d.default_locale)+octet_length(d.article13_notice_schema)
   +COALESCE(octet_length(d.pdf_storage_key),0)+COALESCE(octet_length(d.pdf_storage_version_id),0)
   +COALESCE(octet_length(d.html_effective_source_commitment),0)) AS document_text_bytes
 FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND d.signing_admission_active_id=sqlc.arg(admission_id) AND d.signing_admission_policy='pdf-static-v1'
  AND d.status IN('sent','in_progress')
  AND current_setting('transaction_isolation')='read committed'
), field_count_guard AS MATERIALIZED (
 SELECT count(*)::bigint AS n FROM document_fields f JOIN parent d ON d.id=f.document_id
), field_locks AS MATERIALIZED (
 SELECT f.id FROM document_fields f JOIN parent d ON d.id=f.document_id
 CROSS JOIN field_count_guard g WHERE g.n BETWEEN 1 AND 1000 ORDER BY f.id FOR UPDATE OF f
), field_lock_guard AS MATERIALIZED (SELECT count(*)::bigint AS n FROM field_locks), branding_locks AS MATERIALIZED (
 SELECT b.document_id FROM document_branding_override b JOIN parent d ON d.id=b.document_id
 CROSS JOIN field_lock_guard g WHERE g.n BETWEEN 1 AND 1000 FOR SHARE OF b
), branding_lock_guard AS MATERIALIZED (SELECT count(*)::bigint AS n FROM branding_locks), document_size_locks AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.html_origin_wire_bytes,m.html_current_wire_bytes,m.variables_wire_bytes
 FROM document_signing_policy_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN branding_lock_guard g
 WHERE m.measurement_server_version_num=current_setting('server_version_num')::integer
 FOR SHARE OF m
), document_size_guard AS MATERIALIZED (SELECT count(*)::bigint AS n FROM document_size_locks), field_size_locks AS MATERIALIZED (
 SELECT m.field_id,m.options_wire_bytes FROM field_signing_policy_sizes_v1 m
 JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN document_size_guard g JOIN field_locks f ON f.id=m.field_id
 WHERE m.measurement_server_version_num=current_setting('server_version_num')::integer
 ORDER BY m.field_id FOR SHARE OF m
), cache_guard AS MATERIALIZED (SELECT count(*)::bigint AS n FROM field_size_locks), parties AS MATERIALIZED (
 SELECT count(*)::bigint AS party_count,
  COALESCE(sum(octet_length(r.name)::numeric+octet_length(r.email)+octet_length(r.role)+octet_length(r.status)),0) AS party_text_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id CROSS JOIN cache_guard cg
), fields AS MATERIALIZED (
 SELECT count(*)::bigint AS field_count,count(m.field_id)::bigint AS measured_field_count,
  COALESCE(sum(octet_length(f.type)::numeric+COALESCE(octet_length(f.label),0)),0) AS field_text_bytes,
  COALESCE(sum(m.options_wire_bytes::numeric),0) AS field_options_wire_bytes
 FROM document_fields f JOIN parent d ON d.id=f.document_id
 CROSS JOIN cache_guard cg CROSS JOIN field_lock_guard fg
 LEFT JOIN field_size_locks m ON m.field_id=f.id
 WHERE cg.n=fg.n AND fg.n BETWEEN 1 AND 1000
), branding AS MATERIALIZED (
 SELECT count(*)::bigint AS branding_count,
  COALESCE(sum(COALESCE(octet_length(b.primary_hex),0)::numeric+COALESCE(octet_length(b.accent_hex),0)
   +COALESCE(octet_length(b.surface_hex),0)+COALESCE(octet_length(b.text_hex),0)+COALESCE(octet_length(b.muted_hex),0)
   +COALESCE(octet_length(b.logo_url),0)+COALESCE(octet_length(b.logo_alt),0)+COALESCE(octet_length(b.font_heading),0)
   +COALESCE(octet_length(b.font_body),0)+COALESCE(octet_length(b.signature_color),0)),0) AS branding_text_bytes
 FROM document_branding_override b JOIN parent d ON d.id=b.document_id
 CROSS JOIN cache_guard cg CROSS JOIN branding_lock_guard bg
)
SELECT d.id AS document_id,d.org_id,d.signing_admission_active_id AS admission_id,
 d.has_html_source,d.has_current_html_source,m.html_origin_wire_bytes,m.html_current_wire_bytes,m.variables_wire_bytes,
 p.party_count,f.field_count,b.branding_count,
 (d.document_text_bytes+p.party_text_bytes+f.field_text_bytes+b.branding_text_bytes)::bigint AS projected_text_bytes,
 f.field_options_wire_bytes::bigint AS field_options_wire_bytes,
 (m.html_origin_wire_bytes::numeric+m.html_current_wire_bytes+m.variables_wire_bytes
  +d.document_text_bytes+p.party_text_bytes+f.field_text_bytes+b.branding_text_bytes+f.field_options_wire_bytes
  +4096*(1+p.party_count+f.field_count+b.branding_count))::bigint AS policy_bytes
FROM parent d JOIN document_size_locks m ON m.document_id=d.id AND m.org_id=d.org_id
 CROSS JOIN parties p CROSS JOIN fields f CROSS JOIN branding b
 CROSS JOIN cache_guard cg CROSS JOIN field_lock_guard fg CROSS JOIN branding_lock_guard bg
WHERE fg.n=f.field_count AND cg.n=f.field_count AND bg.n=b.branding_count
 AND p.party_count BETWEEN 1 AND 100 AND f.field_count BETWEEN 1 AND 1000
 AND f.field_count=f.measured_field_count AND b.branding_count BETWEEN 0 AND 1
 AND ((NOT d.has_html_source AND m.html_origin_wire_bytes=0) OR (d.has_html_source AND m.html_origin_wire_bytes>0))
 AND ((NOT d.has_current_html_source AND m.html_current_wire_bytes=0) OR (d.has_current_html_source AND m.html_current_wire_bytes>0));

-- Only invoke this maintenance query AFTER an actual trusted backfill loan.
-- It locks the parent before the size-cache row, never loads a document model,
-- and the cache guard derives actual bytes. The placeholder zeros are discarded
-- by that guard; they are not trusted declarations or quota/READY fabrication.
-- name: MeasureSignatureFitHTMLPolicyDocumentV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 FOR UPDATE OF d NOWAIT
)
INSERT INTO document_signing_policy_sizes_v1(document_id,org_id,html_origin_wire_bytes,html_current_wire_bytes,variables_wire_bytes,measurement_server_version_num,measured_at)
SELECT p.id,p.org_id,0,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent p
ON CONFLICT(document_id) DO UPDATE SET org_id=EXCLUDED.org_id
RETURNING *;
-- A bound maintenance writer similarly measures each real scoped field AFTER
-- the same complete parent/ordered-participant/field fences and retained loan.
-- name: MeasureSignatureFitHTMLPolicyFieldV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id) FOR UPDATE OF d NOWAIT
), field AS MATERIALIZED (
 SELECT f.id,f.document_id,d.org_id FROM document_fields f JOIN parent d ON d.id=f.document_id
 WHERE f.id=sqlc.arg(field_id) FOR UPDATE OF f NOWAIT
)
INSERT INTO field_signing_policy_sizes_v1(field_id,document_id,org_id,options_wire_bytes,measurement_server_version_num,measured_at)
SELECT f.id,f.document_id,f.org_id,0,current_setting('server_version_num')::integer,clock_timestamp() FROM field f
ON CONFLICT(field_id) DO UPDATE SET document_id=EXCLUDED.document_id,org_id=EXCLUDED.org_id
RETURNING *;

-- Actual policy-only projections. Caller holds the SAME admitted session and
-- complete entity/field/branding/cache locks from the size header. No SELECT*.
-- Preserve raw HTML/variables/pins; never substitute metadata or template latest.
-- name: ReadSignatureFitPolicyDocumentV1 :one
SELECT d.id,d.org_id,d.template_id,d.name,d.status,d.routing_mode,d.source_kind,
 d.variables_json,d.pdf_storage_key,CASE WHEN octet_length(d.pdf_sha256)=32 THEN d.pdf_sha256 ELSE NULL::bytea END AS pdf_sha256,d.pdf_storage_version_id,
 d.expires_at,d.sent_at,d.parent_envelope_id,d.is_envelope,d.routing_tier,d.lawful_basis,d.deleted_at,d.default_locale,d.requires_signature,
 d.evidence_version_pins_required,d.article13_notice_epoch_at,d.article13_notice_schema,d.article13_notice_epoch_v61_committed,
 d.html_source_json,CASE WHEN octet_length(d.html_reviewed_pdf_sha256)=32 THEN d.html_reviewed_pdf_sha256 ELSE NULL::bytea END AS html_reviewed_pdf_sha256,d.html_reviewed_by,d.html_reviewed_at,
 d.html_current_materialization_id,d.html_current_source_json,d.html_current_page_count,d.html_current_materialization_sequence,
 d.html_reviewed_materialization_id,d.html_effective_source_commitment,d.signing_admission_policy,d.signing_admission_active_id
FROM documents d JOIN document_signing_policy_sizes_v1 m ON m.document_id=d.id AND m.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id) AND d.signing_admission_active_id=sqlc.arg(admission_id)
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.html_origin_wire_bytes=sqlc.arg(expected_origin_wire_bytes)
 AND m.html_current_wire_bytes=sqlc.arg(expected_current_wire_bytes)
 AND m.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes);

-- name: ReadSignatureFitPolicyRecipientV1 :one
SELECT r.id,r.document_id,r.role,r.email,r.name,r.order_index,r.status,
 CASE WHEN octet_length(r.magic_token_hash)=32 THEN r.magic_token_hash ELSE NULL::bytea END AS magic_token_hash,
 r.sent_at,r.first_viewed_at,r.signed_at,r.created_at,r.magic_token_expires_at
FROM recipients r JOIN documents d ON d.id=r.document_id
WHERE r.id=sqlc.arg(recipient_id) AND r.document_id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id);

-- name: ListSignatureFitPolicyPartiesV1 :many
SELECT r.id,r.document_id,r.role,r.email,r.name,r.order_index,r.status,r.created_at
FROM recipients r JOIN documents d ON d.id=r.document_id
WHERE r.document_id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
ORDER BY r.order_index,r.created_at;

-- name: ListSignatureFitPolicyFieldsV1 :many
SELECT f.id,f.document_id,f.recipient_id,f.type,f.page,f.x_pct,f.y_pct,f.w_pct,f.h_pct,
 f.required,f.label,f.options_json,m.options_wire_bytes
FROM document_fields f JOIN documents d ON d.id=f.document_id
JOIN field_signing_policy_sizes_v1 m ON m.field_id=f.id AND m.document_id=d.id AND m.org_id=d.org_id
WHERE f.document_id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
ORDER BY f.id;

-- name: ReadSignatureFitPolicyControllerV1 :one
SELECT c.document_id,c.org_id,c.lawful_basis,c.confirmed_at,c.confirmed_by,c.via,c.controller_name,c.controller_contact
FROM document_lawful_basis_confirmations c
WHERE c.document_id=sqlc.arg(document_id) AND c.org_id=sqlc.arg(org_id);

-- name: ReadSignatureFitPolicyOrgV1 :one
SELECT id,name FROM orgs WHERE id=sqlc.arg(org_id);

-- name: ReadSignatureFitPolicyBrandingV1 :one
SELECT b.document_id,b.primary_hex,b.accent_hex,b.surface_hex,b.text_hex,b.muted_hex,
 b.logo_url,b.logo_alt,b.font_heading,b.font_body,b.signature_color
FROM document_branding_override b JOIN documents d ON d.id=b.document_id
WHERE b.document_id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id);
