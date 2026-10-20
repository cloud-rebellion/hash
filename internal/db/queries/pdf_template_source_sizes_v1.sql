-- Native PDF-template source contract. Header loans precede SQL, source
-- parent precedes cache locks, and full models require same locked scalar
-- observations. Missing/old caches refuse; readers never invoke measurement.

-- name: GetPDFTemplateSourceHeaderForShareV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,(octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint AS raw_text_bytes
 FROM templates t WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL
 FOR SHARE OF t
), cache AS MATERIALIZED (
 SELECT m.template_id,m.org_id,m.source_kind,m.master_wire_bytes,m.variables_wire_bytes,m.blocks_wire_bytes,m.fields_wire_bytes,m.sanitization_wire_bytes,m.measurement_server_version_num
 FROM pdf_template_source_sizes_v1 m JOIN parent t ON t.id=m.template_id AND t.org_id=m.org_id
 AND t.created_at=m.template_created_at AND t.updated_at=m.template_updated_at AND t.version=m.template_version AND t.source_kind=m.source_kind
 FOR SHARE OF m
)
SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,t.raw_text_bytes,
 COALESCE(m.master_wire_bytes,-1::bigint)::bigint AS master_wire_bytes,
 COALESCE(m.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(m.fields_wire_bytes,-1::bigint)::bigint AS fields_wire_bytes,
 COALESCE(m.sanitization_wire_bytes,-1::bigint)::bigint AS sanitization_wire_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent t LEFT JOIN cache m ON t.id=m.template_id AND t.org_id=m.org_id;

-- name: GetPDFTemplateSourceHeaderForUpdateV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,(octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint AS raw_text_bytes
 FROM templates t WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL
 FOR UPDATE OF t
), cache AS MATERIALIZED (
 SELECT m.template_id,m.org_id,m.source_kind,m.master_wire_bytes,m.variables_wire_bytes,m.blocks_wire_bytes,m.fields_wire_bytes,m.sanitization_wire_bytes,m.measurement_server_version_num
 FROM pdf_template_source_sizes_v1 m JOIN parent t ON t.id=m.template_id AND t.org_id=m.org_id
 AND t.created_at=m.template_created_at AND t.updated_at=m.template_updated_at AND t.version=m.template_version AND t.source_kind=m.source_kind
 FOR SHARE OF m
)
SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,t.raw_text_bytes,
 COALESCE(m.master_wire_bytes,-1::bigint)::bigint AS master_wire_bytes,
 COALESCE(m.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(m.fields_wire_bytes,-1::bigint)::bigint AS fields_wire_bytes,
 COALESCE(m.sanitization_wire_bytes,-1::bigint)::bigint AS sanitization_wire_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent t LEFT JOIN cache m ON t.id=m.template_id AND t.org_id=m.org_id;

-- name: ReadPDFTemplateSourceV1 :one
SELECT t.* FROM templates t JOIN pdf_template_source_sizes_v1 m ON t.id=m.template_id AND t.org_id=m.org_id
 AND t.created_at=m.template_created_at AND t.updated_at=m.template_updated_at AND t.version=m.template_version AND t.source_kind=m.source_kind
WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL AND t.source_kind='pdf'
 AND t.created_at=sqlc.arg(expected_created_at)::timestamptz AND t.updated_at=sqlc.arg(expected_updated_at)::timestamptz AND t.version=sqlc.arg(expected_version)::integer
 AND (octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.master_wire_bytes=sqlc.arg(expected_master_wire_bytes)::bigint
 AND m.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes)::bigint
 AND m.blocks_wire_bytes=sqlc.arg(expected_blocks_wire_bytes)::bigint
 AND m.fields_wire_bytes=sqlc.arg(expected_fields_wire_bytes)::bigint
 AND m.sanitization_wire_bytes=sqlc.arg(expected_sanitization_wire_bytes)::bigint;

-- name: MeasurePDFTemplateSourceV1 :one
-- Only an actual bounded fresh/update producer or independently admitted
-- explicit maintenance owner may derive source metadata. No normal reader
-- calls this query; placeholder sizes/stamps are replaced by the M97 guard.
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.created_at,t.updated_at,t.version FROM templates t
 WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
 AND t.source_kind='pdf' AND t.archived_at IS NULL
 AND t.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND t.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND t.version=sqlc.arg(expected_version)::integer
 FOR UPDATE OF t NOWAIT
)
INSERT INTO pdf_template_source_sizes_v1(template_id,org_id,template_created_at,template_updated_at,template_version,master_wire_bytes,variables_wire_bytes,blocks_wire_bytes,fields_wire_bytes,sanitization_wire_bytes,measurement_server_version_num,measured_at)
SELECT t.id,t.org_id,t.created_at,t.updated_at,t.version,0,0,0,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent t
ON CONFLICT(template_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;

-- name: CreateFreshPDFTemplateSourceV1 :one
-- Private native operation scope ID belongs only to this actual fresh INSERT.
INSERT INTO templates(id,org_id,name,source_kind,pdf_storage_key,pdf_sha256,pdf_storage_version_id,evidence_version_pin_required,page_count,fields_json,created_by,pdf_sanitization_report)
VALUES(sqlc.arg(id)::uuid,sqlc.arg(org_id)::uuid,sqlc.arg(name)::text,'pdf',sqlc.arg(pdf_storage_key)::text,sqlc.arg(pdf_sha256)::bytea,sqlc.arg(pdf_storage_version_id)::text,sqlc.arg(evidence_version_pin_required)::boolean,sqlc.arg(page_count)::integer,sqlc.arg(fields_json)::jsonb,sqlc.arg(created_by)::uuid,sqlc.narg(pdf_sanitization_report)::jsonb)
RETURNING *;

-- Shared finite non-HTML Template-row contract. Actual fixed consumers check
-- their PDF/blocks purpose from the scalar parent header BEFORE full body.
-- No HTML body, approval or historical repair is available through this path.
-- name: GetNonHTMLTemplateSourceHeaderForShareV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,(octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint AS raw_text_bytes
 FROM templates t WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL
 FOR SHARE OF t
), cache AS MATERIALIZED (
 SELECT m.template_id,m.org_id,m.source_kind,m.master_wire_bytes,m.variables_wire_bytes,m.blocks_wire_bytes,m.fields_wire_bytes,m.sanitization_wire_bytes,m.measurement_server_version_num
 FROM pdf_template_source_sizes_v1 m JOIN parent t ON t.id=m.template_id AND t.org_id=m.org_id
 AND t.created_at=m.template_created_at AND t.updated_at=m.template_updated_at AND t.version=m.template_version AND t.source_kind=m.source_kind
 FOR SHARE OF m
)
SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,t.raw_text_bytes,
 COALESCE(m.master_wire_bytes,-1::bigint)::bigint AS master_wire_bytes,
 COALESCE(m.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(m.fields_wire_bytes,-1::bigint)::bigint AS fields_wire_bytes,
 COALESCE(m.sanitization_wire_bytes,-1::bigint)::bigint AS sanitization_wire_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent t LEFT JOIN cache m ON t.id=m.template_id AND t.org_id=m.org_id;

-- name: GetNonHTMLTemplateSourceHeaderForUpdateV1 :one
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,(octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint AS raw_text_bytes
 FROM templates t WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL
 FOR UPDATE OF t
), cache AS MATERIALIZED (
 SELECT m.template_id,m.org_id,m.source_kind,m.master_wire_bytes,m.variables_wire_bytes,m.blocks_wire_bytes,m.fields_wire_bytes,m.sanitization_wire_bytes,m.measurement_server_version_num
 FROM pdf_template_source_sizes_v1 m JOIN parent t ON t.id=m.template_id AND t.org_id=m.org_id
 AND t.created_at=m.template_created_at AND t.updated_at=m.template_updated_at AND t.version=m.template_version AND t.source_kind=m.source_kind
 FOR SHARE OF m
)
SELECT t.id,t.org_id,t.source_kind,t.version,t.created_at,t.updated_at,t.raw_text_bytes,
 COALESCE(m.master_wire_bytes,-1::bigint)::bigint AS master_wire_bytes,
 COALESCE(m.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(m.fields_wire_bytes,-1::bigint)::bigint AS fields_wire_bytes,
 COALESCE(m.sanitization_wire_bytes,-1::bigint)::bigint AS sanitization_wire_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent t LEFT JOIN cache m ON t.id=m.template_id AND t.org_id=m.org_id;


-- name: ReadNonHTMLTemplateSourceV1 :one
SELECT t.* FROM templates t JOIN pdf_template_source_sizes_v1 m ON t.id=m.template_id AND t.org_id=m.org_id
 AND t.created_at=m.template_created_at AND t.updated_at=m.template_updated_at AND t.version=m.template_version AND t.source_kind=m.source_kind
WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid AND t.archived_at IS NULL AND t.source_kind=sqlc.arg(expected_source_kind)::text AND t.source_kind IN ('pdf','blocks')
 AND t.created_at=sqlc.arg(expected_created_at)::timestamptz AND t.updated_at=sqlc.arg(expected_updated_at)::timestamptz AND t.version=sqlc.arg(expected_version)::integer
 AND (octet_length(t.name)::numeric+octet_length(t.source_kind)+COALESCE(octet_length(t.pdf_storage_key),0)+COALESCE(octet_length(t.pdf_storage_version_id),0)+COALESCE(octet_length(t.pdf_sha256),0)+COALESCE(octet_length(t.html_content_sha256),0))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.master_wire_bytes=sqlc.arg(expected_master_wire_bytes)::bigint
 AND m.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes)::bigint
 AND m.blocks_wire_bytes=sqlc.arg(expected_blocks_wire_bytes)::bigint
 AND m.fields_wire_bytes=sqlc.arg(expected_fields_wire_bytes)::bigint
 AND m.sanitization_wire_bytes=sqlc.arg(expected_sanitization_wire_bytes)::bigint;


-- name: MeasureNonHTMLTemplateSourceV1 :one
-- Only an actual bounded fresh/update producer or independently admitted
-- explicit maintenance owner may derive source metadata. No normal reader
-- calls this query; placeholder sizes/stamps are replaced by the M97 guard.
WITH parent AS MATERIALIZED (
 SELECT t.id,t.org_id,t.created_at,t.updated_at,t.version FROM templates t
 WHERE t.id=sqlc.arg(template_id)::uuid AND t.org_id=sqlc.arg(org_id)::uuid
 AND t.source_kind IN ('pdf','blocks') AND t.archived_at IS NULL
 AND t.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND t.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND t.version=sqlc.arg(expected_version)::integer
 FOR UPDATE OF t NOWAIT
)
INSERT INTO pdf_template_source_sizes_v1(template_id,org_id,template_created_at,template_updated_at,template_version,master_wire_bytes,variables_wire_bytes,blocks_wire_bytes,fields_wire_bytes,sanitization_wire_bytes,measurement_server_version_num,measured_at)
SELECT t.id,t.org_id,t.created_at,t.updated_at,t.version,0,0,0,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent t
ON CONFLICT(template_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;
