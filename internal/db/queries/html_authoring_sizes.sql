-- Source-only paired M92 query contract. Real bounded cheap-header allowance
-- precedes each header. SAME owned READ COMMITTED transaction/session retains
-- parent -> revision (where present) -> ordered cache locks through body read,
-- original credential revalidation, commit and retained consumer lifetime.
-- Headers never select JSONB bodies, JSONB::text, JSONB equality or expanded
-- measurement. Missing (-1) or differing PostgreSQL measurement version refuses
-- in native code before body acquisition; callers cannot declare READY here.
-- name: GetHTMLAuthoringTemplateHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.version,
  CASE WHEN octet_length(t.html_content_sha256)=32 THEN t.html_content_sha256 ELSE NULL::bytea END AS content_sha256,
  (octet_length(t.name)::numeric+octet_length(t.source_kind)
   +COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)
   +COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint AS raw_text_bytes
 FROM templates t WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
  AND t.source_kind='html' AND t.archived_at IS NULL
 FOR SHARE OF t
), cache AS MATERIALIZED (
 SELECT m.template_id,m.org_id,m.master_wire_bytes,m.variables_wire_bytes,m.blocks_wire_bytes,
  m.fields_wire_bytes,m.sanitization_wire_bytes,m.measurement_server_version_num
 FROM html_authoring_template_sizes_v1 m JOIN parent p ON p.id=m.template_id AND p.org_id=m.org_id
 FOR SHARE OF m
)
SELECT p.id,p.org_id,p.version,p.content_sha256,
 COALESCE(m.master_wire_bytes,-1::bigint)::bigint AS master_wire_bytes,
 COALESCE(m.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(m.fields_wire_bytes,-1::bigint)::bigint AS fields_wire_bytes,
 COALESCE(m.sanitization_wire_bytes,-1::bigint)::bigint AS sanitization_wire_bytes,
 p.raw_text_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent p LEFT JOIN cache m ON m.template_id=p.id AND m.org_id=p.org_id;

-- name: GetHTMLAuthoringTemplateHeaderForUpdateV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.version,
  CASE WHEN octet_length(t.html_content_sha256)=32 THEN t.html_content_sha256 ELSE NULL::bytea END AS content_sha256,
  (octet_length(t.name)::numeric+octet_length(t.source_kind)
   +COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)
   +COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint AS raw_text_bytes
 FROM templates t WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
  AND t.source_kind='html' AND t.archived_at IS NULL
 FOR UPDATE OF t
), cache AS MATERIALIZED (
 SELECT m.template_id,m.org_id,m.master_wire_bytes,m.variables_wire_bytes,m.blocks_wire_bytes,
  m.fields_wire_bytes,m.sanitization_wire_bytes,m.measurement_server_version_num
 FROM html_authoring_template_sizes_v1 m JOIN parent p ON p.id=m.template_id AND p.org_id=m.org_id
 FOR SHARE OF m
)
SELECT p.id,p.org_id,p.version,p.content_sha256,
 COALESCE(m.master_wire_bytes,-1::bigint)::bigint AS master_wire_bytes,
 COALESCE(m.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(m.fields_wire_bytes,-1::bigint)::bigint AS fields_wire_bytes,
 COALESCE(m.sanitization_wire_bytes,-1::bigint)::bigint AS sanitization_wire_bytes,
 p.raw_text_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent p LEFT JOIN cache m ON m.template_id=p.id AND m.org_id=p.org_id;

-- name: GetHTMLAuthoringRevisionHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id FROM templates t
 WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
  AND t.source_kind='html' AND t.archived_at IS NULL
 FOR SHARE OF t
), revision AS MATERIALIZED (
 SELECT r.template_id,r.org_id,r.version,
  CASE WHEN octet_length(r.content_sha256)=32 THEN r.content_sha256 ELSE NULL::bytea END AS content_sha256,
  r.approved_by,r.approved_at
 FROM html_template_revisions r JOIN parent p ON p.id=r.template_id AND p.org_id=r.org_id
 WHERE r.version=sqlc.arg(version)::integer
 FOR SHARE OF r
), cache AS MATERIALIZED (
 SELECT m.template_id,m.org_id,m.version,m.master_wire_bytes,m.variables_wire_bytes,m.measurement_server_version_num
 FROM html_authoring_revision_sizes_v1 m JOIN revision r
  ON r.template_id=m.template_id AND r.org_id=m.org_id AND r.version=m.version
 FOR SHARE OF m
)
SELECT r.template_id,r.org_id,r.version,r.content_sha256,r.approved_by,r.approved_at,
 COALESCE(m.master_wire_bytes,-1::bigint)::bigint AS master_wire_bytes,
 COALESCE(m.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM revision r LEFT JOIN cache m ON m.template_id=r.template_id AND m.org_id=r.org_id AND m.version=r.version;

-- name: ReadHTMLAuthoringTemplateV1 :one
-- Only after the real body loan and original header binding; actual model, no
-- fabricated partial Template and no latest-version replacement.
SELECT t.* FROM templates t JOIN html_authoring_template_sizes_v1 m ON m.template_id=t.id AND m.org_id=t.org_id
WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
 AND t.source_kind='html' AND t.archived_at IS NULL
 AND t.version=sqlc.arg(expected_version)::integer
 AND t.html_content_sha256=sqlc.arg(expected_content_sha256)::bytea
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.master_wire_bytes=sqlc.arg(expected_master_wire_bytes)::bigint
 AND m.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes)::bigint
 AND m.blocks_wire_bytes=sqlc.arg(expected_blocks_wire_bytes)::bigint
 AND m.fields_wire_bytes=sqlc.arg(expected_fields_wire_bytes)::bigint
 AND m.sanitization_wire_bytes=sqlc.arg(expected_sanitization_wire_bytes)::bigint;

-- name: ReadHTMLAuthoringRevisionV1 :one
SELECT r.* FROM html_template_revisions r
JOIN templates t ON t.id=r.template_id AND t.org_id=r.org_id
JOIN html_authoring_revision_sizes_v1 m ON m.template_id=r.template_id AND m.org_id=r.org_id AND m.version=r.version
WHERE r.template_id=sqlc.arg(template_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
 AND r.version=sqlc.arg(version)::integer AND r.content_sha256=sqlc.arg(expected_content_sha256)::bytea
 AND t.source_kind='html' AND t.archived_at IS NULL
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.master_wire_bytes=sqlc.arg(expected_master_wire_bytes)::bigint
 AND m.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes)::bigint;

-- These are expanded measurements for genuine fresh bounded native producers.
-- A cache guard overwrites every size/timestamp from locked actual source; zero
-- placeholders cannot understate. No automatic refresh or old uncached replay
-- repair is permitted. Parent locks precede cache mutation, including conflict.
-- name: MeasureHTMLAuthoringTemplateV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id FROM templates t
 WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
  AND t.source_kind='html' AND t.archived_at IS NULL FOR UPDATE OF t NOWAIT
)
INSERT INTO html_authoring_template_sizes_v1(template_id,org_id,master_wire_bytes,variables_wire_bytes,blocks_wire_bytes,fields_wire_bytes,sanitization_wire_bytes,measurement_server_version_num,measured_at)
SELECT p.id,p.org_id,0,0,0,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent p
ON CONFLICT(template_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;

-- name: MeasureHTMLAuthoringRevisionV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id FROM templates t
 WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
  AND t.source_kind='html' AND t.archived_at IS NULL FOR UPDATE OF t NOWAIT
), revision AS MATERIALIZED (
 SELECT r.template_id,r.org_id,r.version FROM html_template_revisions r
 JOIN parent p ON p.id=r.template_id AND p.org_id=r.org_id
 WHERE r.version=sqlc.arg(version)::integer FOR SHARE OF r NOWAIT
)
INSERT INTO html_authoring_revision_sizes_v1(template_id,org_id,version,master_wire_bytes,variables_wire_bytes,measurement_server_version_num,measured_at)
SELECT r.template_id,r.org_id,r.version,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM revision r
ON CONFLICT(template_id,version) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;

-- name: GetHTMLCreationResponseHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at,(octet_length(d.name)::numeric+octet_length(d.status)+octet_length(d.routing_mode)+octet_length(d.source_kind)
   +COALESCE(octet_length(d.pdf_storage_key),0)+COALESCE(octet_length(d.pdf_sha256),0)
   +COALESCE(octet_length(d.final_pdf_key),0)+COALESCE(octet_length(d.audit_cert_key),0)
   +octet_length(d.default_locale)+COALESCE(octet_length(d.html_effective_source_commitment),0))::bigint AS raw_text_bytes
 FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR SHARE OF d
), response_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.blocks_wire_bytes,m.metadata_wire_bytes,m.measurement_server_version_num
 FROM html_creation_response_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id FOR SHARE OF m
), response_cache_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM response_cache), policy_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.variables_wire_bytes,m.measurement_server_version_num
 FROM document_signing_policy_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN response_cache_done g FOR SHARE OF m
)
SELECT d.id,d.org_id,d.updated_at,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(p.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.metadata_wire_bytes,-1::bigint)::bigint AS metadata_wire_bytes,
 d.raw_text_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 COALESCE(p.measurement_server_version_num,-1::integer)::integer AS policy_measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent d LEFT JOIN response_cache m ON m.document_id=d.id AND m.org_id=d.org_id
 LEFT JOIN policy_cache p ON p.document_id=d.id AND p.org_id=d.org_id;

-- name: ReadHTMLCreationResponseV1 :one
-- Preserve the real documentResponse projection and historical raw digest hex
-- behavior. Digests/text are charged by the cheap header. No origin/current
-- source JSON bodies, source reconstruction or fabricated Document model.
SELECT d.id,d.org_id,d.template_id,d.name,d.status,d.routing_mode,d.source_kind,d.requires_signature,
 d.blocks_json,d.variables_json,d.pdf_storage_key,d.pdf_sha256,d.final_pdf_key,d.audit_cert_key,
 d.expires_at,d.sent_at,d.completed_at,d.sender_id,d.metadata,d.default_locale,d.created_at,d.updated_at,
 (d.html_source_json IS NOT NULL)::boolean AS has_html_source,
 d.html_effective_source_commitment,d.html_current_materialization_sequence,
 (d.html_source_json IS NOT NULL AND (
  d.html_reviewed_by IS NULL OR d.html_reviewed_at IS NULL OR COALESCE(octet_length(d.pdf_sha256)<>32,true)
  OR NOT CASE WHEN octet_length(d.html_reviewed_pdf_sha256)=32 AND octet_length(d.pdf_sha256)=32
   THEN d.html_reviewed_pdf_sha256=d.pdf_sha256 ELSE false END
  OR (d.html_current_materialization_id IS NOT NULL AND
   (d.html_reviewed_materialization_id IS NULL OR d.html_reviewed_materialization_id<>d.html_current_materialization_id))
 ))::boolean AS html_review_required
FROM documents d JOIN html_creation_response_sizes_v1 m ON m.document_id=d.id AND m.org_id=d.org_id
 JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND p.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.blocks_wire_bytes=sqlc.arg(expected_blocks_wire_bytes)::bigint
 AND p.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes)::bigint
 AND m.metadata_wire_bytes=sqlc.arg(expected_metadata_wire_bytes)::bigint;

-- name: MeasureHTMLCreationResponseV1 :one
-- Genuine fresh native HTML-document creator only: blocks are NULL and metadata
-- is the literal {} at this producer stage, so its retained creation loan covers
-- this measurement. Old cached/missing replay never calls this query.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL AND d.status='draft' AND d.source_kind='pdf' AND d.html_source_json IS NOT NULL
 FOR UPDATE OF d NOWAIT
)
INSERT INTO html_creation_response_sizes_v1(document_id,org_id,blocks_wire_bytes,metadata_wire_bytes,measurement_server_version_num,measured_at)
SELECT d.id,d.org_id,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent d
ON CONFLICT(document_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;

-- These cheap scalar headers extend the same actual reader allowance before
-- unchanged trusted authoring/CRM model helpers. No credential data is returned.
-- Native caller then acquires checked raw-derived body capacity and retains SAME
-- session/locks through the exact original-credential recheck.
-- name: GetHTMLAuthoringActorHeaderV1 :one
SELECT u.id AS user_id,u.org_id,
 (octet_length(u.email)::numeric+octet_length(u.name)+octet_length(u.role)+COALESCE(octet_length(u.zitadel_sub),0))::bigint AS raw_text_bytes
FROM users u WHERE u.id=sqlc.arg(user_id)::uuid AND u.org_id=sqlc.arg(org_id)::uuid
FOR SHARE OF u;

-- name: GetHTMLAuthoringOwnerHeaderV1 :one
WITH owner_org AS MATERIALIZED (
 SELECT o.id,(octet_length(o.name)::numeric+octet_length(o.plan)+octet_length(o.change_approval_mode)) AS raw_text_bytes
 FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid FOR NO KEY UPDATE OF o
), member AS MATERIALIZED (
 SELECT u.id AS user_id,u.org_id,
  (octet_length(u.email)::numeric+octet_length(u.name)+octet_length(u.role)+COALESCE(octet_length(u.zitadel_sub),0)) AS raw_text_bytes
 FROM users u JOIN owner_org o ON o.id=u.org_id
 WHERE u.id=sqlc.arg(user_id)::uuid FOR SHARE OF u
)
SELECT u.user_id,u.org_id,(o.raw_text_bytes+u.raw_text_bytes)::bigint AS raw_text_bytes
FROM owner_org o JOIN member u ON u.org_id=o.id;

-- name: GetHTMLAuthoringCRMConnectionHeaderV1 :one
SELECT c.id,c.org_id,
 (octet_length(c.status)::numeric+octet_length(c.origin)+octet_length(c.crm_team_id)+octet_length(c.crm_user_id)
  +COALESCE(octet_length(c.credential_ciphertext),0))::bigint AS raw_text_bytes
FROM crm_connections c WHERE c.org_id=sqlc.arg(org_id)::uuid FOR SHARE OF c;
