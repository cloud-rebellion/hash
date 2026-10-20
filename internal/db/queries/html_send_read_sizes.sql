-- SOURCE-ONLY owned standalone HTML Send projections. No new DDL or backfill.
-- The original real parent/session, same-transaction locks and native work owner
-- remain mandatory. Header equality never substitutes for that ownership.

-- name: GetHTMLSendDocumentStateHeaderV1 :one
SELECT d.id,d.org_id,d.updated_at,d.expires_at,d.sender_id,d.is_envelope,
 d.parent_envelope_id,d.requires_signature,
 (d.html_source_json IS NOT NULL)::boolean AS has_html_source,
 CASE WHEN octet_length(d.source_kind)=3 THEN d.source_kind='pdf' ELSE false END AS is_pdf_source,
 CASE WHEN octet_length(d.status)<=17 THEN d.status ELSE ''::text END AS bounded_status,
 d.evidence_version_pins_required,d.sent_at,d.article13_notice_epoch_at,
 d.article13_notice_epoch_v61_committed,
 CASE WHEN octet_length(d.article13_notice_schema)=19
      THEN d.article13_notice_schema='hash-a13-2026-08-31' ELSE false END AS has_supported_article13_notice_schema,
 EXISTS(SELECT 1 FROM document_package_send_attempts_v1 a WHERE a.document_id=d.id AND a.org_id=d.org_id)::boolean AS has_package_send_history
FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d;

-- name: GetHTMLSendCollectionReadHeaderV1 :one
-- SCALAR-ONLY before collection admission: no ordered row IDs, variable keys,
-- cache rowsets or scalable materialized CTE. Each aggregate CTE has ONE row.
-- The fixed owner first holds the real parent UPDATE in a preceding statement.
-- Correlated single-PK cache subqueries avoid collecting/hash-materializing
-- field cache rows before their actual row/raw/options loan exists.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=7 THEN d.status IN ('draft','sealing') ELSE false END FOR UPDATE OF d
), recipient_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)::numeric+COALESCE(octet_length(r.name),0)::numeric+COALESCE(octet_length(r.status),0)::numeric+COALESCE(octet_length(r.locale),0)::numeric+COALESCE(octet_length(r.declined_reason),0)::numeric+COALESCE(octet_length(r.magic_token_hash),0)::numeric),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
), field_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(COALESCE((SELECT s.options_wire_bytes FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE COALESCE((SELECT 1 FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)=0)::bigint AS missing_size_count,
 count(*) FILTER (WHERE COALESCE((SELECT s.measurement_server_version_num FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),-1)<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
), binding_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(b.variable_name),0)::numeric+COALESCE(octet_length(b.source_kind),0)::numeric+COALESCE(octet_length(b.source_ref),0)::numeric+COALESCE(octet_length(b.source_path),0)::numeric+COALESCE(octet_length(b.fallback),0)::numeric+COALESCE(octet_length(b.last_value),0)::numeric+COALESCE(octet_length(b.last_error),0)::numeric),0)::bigint AS raw_bytes
 FROM document_variable_bindings b JOIN parent d ON d.id=b.document_id
)
SELECT d.id AS document_id,d.org_id,r.n AS recipient_count,r.raw_bytes AS recipient_raw_bytes,
 f.n AS field_count,f.raw_bytes AS field_raw_bytes,f.options_wire_bytes AS field_options_wire_bytes,
 f.missing_size_count AS field_missing_size_count,f.server_mismatch_count AS field_measurement_server_mismatch_count,
 b.n AS binding_count,b.raw_bytes AS binding_raw_bytes,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent d CROSS JOIN recipient_stats r CROSS JOIN field_stats f CROSS JOIN binding_stats b;

-- name: LockHTMLSendCollectionRowsV1 :one
-- AFTER the native count/raw/options collection loan: materialize and sort only
-- fixed-width identifiers/stamps. Immediate parent FKs fence new committed rows;
-- row/cache SHARE pins use NOWAIT: real M88 invalidation can lock row->parent.
-- Rows deleted meanwhile can only reduce the paid count. Existing text may grow
-- before SHARE, so never sort/store a variable_name or any raw model here.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=7 THEN d.status IN ('draft','sealing') ELSE false END FOR UPDATE OF d
), recipient_locks AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR SHARE OF r NOWAIT
), recipient_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM recipient_locks), field_locks AS MATERIALIZED (
 SELECT f.id FROM document_fields f JOIN parent d ON d.id=f.document_id CROSS JOIN recipient_done g
 ORDER BY f.id FOR SHARE OF f NOWAIT
), field_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM field_locks), cache_locks AS MATERIALIZED (
 SELECT s.field_id FROM field_signing_policy_sizes_v1 s JOIN field_locks f ON f.id=s.field_id
 JOIN parent d ON d.id=s.document_id AND d.org_id=s.org_id CROSS JOIN field_done g
 ORDER BY s.field_id FOR SHARE OF s NOWAIT
), cache_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM cache_locks), binding_locks AS MATERIALIZED (
 -- Count-only pins need no unique binding identity: ties are safe under
 -- NOWAIT. Price both fixed timestamp Datums (16 logical bytes), retain the
 -- existing row overhead, and verify the fresh whole header before any body.
 SELECT b.created_at AS row_created_at,b.updated_at AS row_updated_at
 FROM document_variable_bindings b JOIN parent d ON d.id=b.document_id CROSS JOIN cache_done g
 ORDER BY b.created_at,b.updated_at FOR SHARE OF b NOWAIT
), binding_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM binding_locks)
SELECT d.id AS document_id,d.org_id,r.n AS recipient_count,f.n AS field_count,c.n AS field_cache_count,b.n AS binding_count
FROM parent d CROSS JOIN recipient_done r CROSS JOIN field_done f CROSS JOIN cache_done c CROSS JOIN binding_done b;

-- name: VerifyHTMLSendCollectionReadHeaderV1 :one
-- NEW statement after the actual collection loan and row/cache pin call, before
-- ANY body/exposure. READ COMMITTED lock waits can change observed rows; refuse
-- stale lengths/counts/cache server values, including ambiguous zero-row bodies.
-- This scalar receipt grants no row/credential/native-session authority.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=7 THEN d.status IN ('draft','sealing') ELSE false END FOR UPDATE OF d
), recipient_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)::numeric+COALESCE(octet_length(r.name),0)::numeric+COALESCE(octet_length(r.status),0)::numeric+COALESCE(octet_length(r.locale),0)::numeric+COALESCE(octet_length(r.declined_reason),0)::numeric+COALESCE(octet_length(r.magic_token_hash),0)::numeric),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
), field_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(COALESCE((SELECT s.options_wire_bytes FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE COALESCE((SELECT 1 FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),0)=0)::bigint AS missing_size_count,
 count(*) FILTER (WHERE COALESCE((SELECT s.measurement_server_version_num FROM field_signing_policy_sizes_v1 s
  WHERE s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id),-1)<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
), binding_stats AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum(COALESCE(octet_length(b.variable_name),0)::numeric+COALESCE(octet_length(b.source_kind),0)::numeric+COALESCE(octet_length(b.source_ref),0)::numeric+COALESCE(octet_length(b.source_path),0)::numeric+COALESCE(octet_length(b.fallback),0)::numeric+COALESCE(octet_length(b.last_value),0)::numeric+COALESCE(octet_length(b.last_error),0)::numeric),0)::bigint AS raw_bytes
 FROM document_variable_bindings b JOIN parent d ON d.id=b.document_id
)
SELECT d.id AS document_id,d.org_id
FROM parent d CROSS JOIN recipient_stats r CROSS JOIN field_stats f CROSS JOIN binding_stats b
WHERE r.n=sqlc.arg(expected_recipient_count)::bigint AND r.raw_bytes=sqlc.arg(expected_recipient_raw_bytes)::bigint
 AND f.n=sqlc.arg(expected_field_count)::bigint AND f.raw_bytes=sqlc.arg(expected_field_raw_bytes)::bigint
 AND f.options_wire_bytes=sqlc.arg(expected_field_options_wire_bytes)::bigint
 AND f.missing_size_count=0 AND f.server_mismatch_count=0
 AND b.n=sqlc.arg(expected_binding_count)::bigint AND b.raw_bytes=sqlc.arg(expected_binding_raw_bytes)::bigint;

-- name: ListHTMLSendRecipientsV1 :many
-- Exact count/raw guards bind the original header. They confer no authority
-- without its retained SAME native parent/row locks and resource loan.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=7 THEN d.status IN ('draft','sealing') ELSE false END
), actual AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum((COALESCE(octet_length(r.role),0)::numeric+COALESCE(octet_length(r.email),0)::numeric+COALESCE(octet_length(r.name),0)::numeric+COALESCE(octet_length(r.status),0)::numeric+COALESCE(octet_length(r.locale),0)::numeric+COALESCE(octet_length(r.declined_reason),0)::numeric+COALESCE(octet_length(r.magic_token_hash),0)::numeric)::numeric),0)::bigint AS raw_bytes
 FROM recipients r JOIN parent d ON d.id=r.document_id
), admitted AS MATERIALIZED (
 SELECT d.id FROM parent d CROSS JOIN actual a
 WHERE a.n=sqlc.arg(expected_count)::bigint AND a.raw_bytes=sqlc.arg(expected_raw_bytes)::bigint
)
SELECT r.* FROM recipients r JOIN admitted d ON d.id=r.document_id ORDER BY r.order_index,r.created_at;

-- name: ListHTMLSendFieldsV1 :many
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=7 THEN d.status IN ('draft','sealing') ELSE false END
), actual AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum((COALESCE(octet_length(f.type),0)::numeric+COALESCE(octet_length(f.label),0)::numeric+COALESCE(octet_length(f.value),0)::numeric)::numeric),0)::bigint AS raw_bytes,
 COALESCE(sum(s.options_wire_bytes::numeric),0)::bigint AS options_wire_bytes,
 count(*) FILTER (WHERE s.field_id IS NULL)::bigint AS missing_size_count,
 count(*) FILTER (WHERE s.measurement_server_version_num<>current_setting('server_version_num')::integer)::bigint AS server_mismatch_count
 FROM document_fields f JOIN parent d ON d.id=f.document_id
 LEFT JOIN field_signing_policy_sizes_v1 s ON s.field_id=f.id AND s.document_id=d.id AND s.org_id=d.org_id
), admitted AS MATERIALIZED (
 SELECT d.id FROM parent d CROSS JOIN actual a
 WHERE a.n=sqlc.arg(expected_count)::bigint AND a.raw_bytes=sqlc.arg(expected_raw_bytes)::bigint
  AND a.options_wire_bytes=sqlc.arg(expected_options_wire_bytes)::bigint AND a.missing_size_count=0 AND a.server_mismatch_count=0
)
SELECT f.* FROM document_fields f JOIN admitted d ON d.id=f.document_id ORDER BY f.page,f.y_pct,f.x_pct;

-- name: ListHTMLSendBindingsV1 :many
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
  AND CASE WHEN octet_length(d.status)<=7 THEN d.status IN ('draft','sealing') ELSE false END
), actual AS MATERIALIZED (
 SELECT count(*)::bigint AS n,COALESCE(sum((COALESCE(octet_length(b.variable_name),0)::numeric+COALESCE(octet_length(b.source_kind),0)::numeric+COALESCE(octet_length(b.source_ref),0)::numeric+COALESCE(octet_length(b.source_path),0)::numeric+COALESCE(octet_length(b.fallback),0)::numeric+COALESCE(octet_length(b.last_value),0)::numeric+COALESCE(octet_length(b.last_error),0)::numeric)::numeric),0)::bigint AS raw_bytes
 FROM document_variable_bindings b JOIN parent d ON d.id=b.document_id
), admitted AS MATERIALIZED (
 SELECT d.id FROM parent d CROSS JOIN actual a
 WHERE a.n=sqlc.arg(expected_count)::bigint AND a.raw_bytes=sqlc.arg(expected_raw_bytes)::bigint
)
SELECT b.* FROM document_variable_bindings b JOIN admitted d ON d.id=b.document_id ORDER BY b.variable_name;

-- name: GetHTMLSendIntentReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d
)
SELECT i.document_id,i.org_id,i.updated_at,
 (COALESCE(octet_length(i.actor_email),0)::numeric+COALESCE(octet_length(i.actor_ip),0)::numeric+COALESCE(octet_length(i.via),0)::numeric+COALESCE(octet_length(i.tool),0)::numeric+COALESCE(octet_length(i.last_error),0)::numeric)::bigint AS raw_text_bytes,
 i.retention_started_at,i.retention_completed_at,i.retain_until,i.article13_notice_epoch_at,i.presign_execution_id,i.package_send_attempt_id
FROM send_sealing_intents i JOIN parent d ON d.id=i.document_id AND d.org_id=i.org_id FOR UPDATE OF i;

-- name: ReadHTMLSendIntentV1 :one
SELECT i.* FROM send_sealing_intents i JOIN documents d ON d.id=i.document_id AND d.org_id=i.org_id
WHERE i.document_id=sqlc.arg(document_id)::uuid AND i.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND i.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (COALESCE(octet_length(i.actor_email),0)::numeric+COALESCE(octet_length(i.actor_ip),0)::numeric+COALESCE(octet_length(i.via),0)::numeric+COALESCE(octet_length(i.tool),0)::numeric+COALESCE(octet_length(i.last_error),0)::numeric)::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: GetHTMLSendBrandingInputHeaderV1 :one
-- Missing org branding is only an observation; the guarded freeze repeats its
-- cheap presence/length check under its own one-statement MVCC snapshot.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d
), org_theme AS MATERIALIZED (
 SELECT o.org_id,(COALESCE(octet_length(o.primary_hex),0)::numeric+COALESCE(octet_length(o.accent_hex),0)::numeric+COALESCE(octet_length(o.surface_hex),0)::numeric+COALESCE(octet_length(o.text_hex),0)::numeric+COALESCE(octet_length(o.muted_hex),0)::numeric+COALESCE(octet_length(o.logo_url),0)::numeric+COALESCE(octet_length(o.logo_alt),0)::numeric+COALESCE(octet_length(o.font_heading),0)::numeric+COALESCE(octet_length(o.font_body),0)::numeric+COALESCE(octet_length(o.signature_color),0)::numeric)::bigint AS raw_text_bytes
 FROM org_branding o JOIN parent d ON d.org_id=o.org_id FOR SHARE OF o
), org_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM org_theme), document_branding AS MATERIALIZED (
 SELECT b.document_id,(COALESCE(octet_length(b.primary_hex),0)::numeric+COALESCE(octet_length(b.accent_hex),0)::numeric+COALESCE(octet_length(b.surface_hex),0)::numeric+COALESCE(octet_length(b.text_hex),0)::numeric+COALESCE(octet_length(b.muted_hex),0)::numeric+COALESCE(octet_length(b.logo_url),0)::numeric+COALESCE(octet_length(b.logo_alt),0)::numeric+COALESCE(octet_length(b.font_heading),0)::numeric+COALESCE(octet_length(b.font_body),0)::numeric+COALESCE(octet_length(b.signature_color),0)::numeric)::bigint AS raw_text_bytes
 FROM document_branding_override b JOIN parent d ON d.id=b.document_id CROSS JOIN org_done g FOR SHARE OF b
)
SELECT d.id AS document_id,d.org_id,(o.org_id IS NOT NULL)::boolean AS has_org_branding,
 (b.document_id IS NOT NULL)::boolean AS has_document_branding,
 COALESCE(o.raw_text_bytes,0)::bigint AS org_branding_raw_bytes,
 COALESCE(b.raw_text_bytes,0)::bigint AS document_branding_raw_bytes
FROM parent d LEFT JOIN org_theme o ON o.org_id=d.org_id LEFT JOIN document_branding b ON b.document_id=d.id;

-- name: FreezeHTMLSendBrandingV1 :one
-- This is the ORIGINAL complete effective theme SQL, with a no-expansion
-- source-presence/raw guard before any returned theme text. Defaults are actual
-- fixed branding.DefaultBranding fields supplied by the fixed native owner.
WITH admitted AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 LEFT JOIN org_branding o ON o.org_id=d.org_id
 LEFT JOIN document_branding_override b ON b.document_id=d.id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
  AND (o.org_id IS NOT NULL)=sqlc.arg(expected_has_org_branding)::boolean
  AND (b.document_id IS NOT NULL)=sqlc.arg(expected_has_document_branding)::boolean
  AND (COALESCE(octet_length(o.primary_hex),0)::numeric+COALESCE(octet_length(o.accent_hex),0)::numeric+COALESCE(octet_length(o.surface_hex),0)::numeric+COALESCE(octet_length(o.text_hex),0)::numeric+COALESCE(octet_length(o.muted_hex),0)::numeric+COALESCE(octet_length(o.logo_url),0)::numeric+COALESCE(octet_length(o.logo_alt),0)::numeric+COALESCE(octet_length(o.font_heading),0)::numeric+COALESCE(octet_length(o.font_body),0)::numeric+COALESCE(octet_length(o.signature_color),0)::numeric)::bigint=sqlc.arg(expected_org_branding_raw_bytes)::bigint
  AND (COALESCE(octet_length(b.primary_hex),0)::numeric+COALESCE(octet_length(b.accent_hex),0)::numeric+COALESCE(octet_length(b.surface_hex),0)::numeric+COALESCE(octet_length(b.text_hex),0)::numeric+COALESCE(octet_length(b.muted_hex),0)::numeric+COALESCE(octet_length(b.logo_url),0)::numeric+COALESCE(octet_length(b.logo_alt),0)::numeric+COALESCE(octet_length(b.font_heading),0)::numeric+COALESCE(octet_length(b.font_body),0)::numeric+COALESCE(octet_length(b.signature_color),0)::numeric)::bigint=sqlc.arg(expected_document_branding_raw_bytes)::bigint
)
INSERT INTO document_branding_override (
 document_id,primary_hex,accent_hex,surface_hex,text_hex,muted_hex,logo_url,logo_alt,font_heading,font_body,signature_color
)
SELECT d.id,
 COALESCE(NULLIF(existing.primary_hex,''),NULLIF(org.primary_hex,''),sqlc.arg(default_primary_hex)::text),
 COALESCE(NULLIF(existing.accent_hex,''),NULLIF(org.accent_hex,''),sqlc.arg(default_accent_hex)::text),
 COALESCE(NULLIF(existing.surface_hex,''),NULLIF(org.surface_hex,''),sqlc.arg(default_surface_hex)::text),
 COALESCE(NULLIF(existing.text_hex,''),NULLIF(org.text_hex,''),sqlc.arg(default_text_hex)::text),
 COALESCE(NULLIF(existing.muted_hex,''),NULLIF(org.muted_hex,''),sqlc.arg(default_muted_hex)::text),
 CASE WHEN COALESCE(d.html_current_source_json,d.html_source_json)->>'schema_version'='3'
      THEN existing.logo_url ELSE COALESCE(NULLIF(existing.logo_url,''),NULLIF(org.logo_url,''),sqlc.arg(default_logo_url)::text) END,
 CASE WHEN COALESCE(d.html_current_source_json,d.html_source_json)->>'schema_version'='3'
      THEN existing.logo_alt ELSE COALESCE(NULLIF(existing.logo_alt,''),NULLIF(org.logo_alt,''),sqlc.arg(default_logo_alt)::text) END,
 COALESCE(NULLIF(existing.font_heading,''),NULLIF(org.font_heading,''),sqlc.arg(default_font_heading)::text),
 COALESCE(NULLIF(existing.font_body,''),NULLIF(org.font_body,''),sqlc.arg(default_font_body)::text),
 COALESCE(NULLIF(existing.signature_color,''),NULLIF(org.signature_color,''),sqlc.arg(default_signature_color)::text)
FROM admitted a JOIN documents d ON d.id=a.id AND d.org_id=a.org_id
LEFT JOIN org_branding org ON org.org_id=d.org_id
LEFT JOIN document_branding_override existing ON existing.document_id=d.id
ON CONFLICT(document_id) DO UPDATE SET
 primary_hex=EXCLUDED.primary_hex,accent_hex=EXCLUDED.accent_hex,surface_hex=EXCLUDED.surface_hex,
 text_hex=EXCLUDED.text_hex,muted_hex=EXCLUDED.muted_hex,logo_url=EXCLUDED.logo_url,logo_alt=EXCLUDED.logo_alt,
 font_heading=EXCLUDED.font_heading,font_body=EXCLUDED.font_body,signature_color=EXCLUDED.signature_color,updated_at=now()
RETURNING document_id,primary_hex,accent_hex,surface_hex,text_hex,muted_hex,logo_url,logo_alt,font_heading,font_body,signature_color;

-- name: GetHTMLSendInitialPolicyHeaderV1 :one
-- Scalar-only before the original expiry/root/acknowledgement/tier decisions.
-- The retained actual parent lock supplies identity; no JSON/cache is expanded.
SELECT d.id AS document_id,d.org_id,d.updated_at,
 (octet_length(d.routing_tier)::numeric+COALESCE(octet_length(d.pdf_storage_key),0))::bigint AS raw_text_bytes
FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d;

-- name: ReadHTMLSendInitialPolicyV1 :one
-- After native raw-body admission on the SAME locked row. No partial Document
-- is manufactured; this is the exact original small policy input projection.
SELECT d.id AS document_id,d.org_id,d.updated_at,d.routing_tier,d.pdf_storage_key,
 COALESCE(octet_length(d.pdf_sha256),0)::bigint AS pdf_sha256_bytes
FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (octet_length(d.routing_tier)::numeric+COALESCE(octet_length(d.pdf_storage_key),0))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;
