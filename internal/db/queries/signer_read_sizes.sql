-- Source-only full signer-read contract. Native caller acquires the genuine
-- global-only unknown-org probe lane BEFORE the first SQL operation, then binds
-- the actual unique probed org/recipient/document into one owned scoped session.
-- Scope metadata is not a bearer/actor, work, readiness or mutation capability.
-- Body loans precede every model/JSONB projection; SAME transaction retains
-- actual parent/recipient/controller/org/cache locks and original credentials.
-- No header JSONB output/comparison/expansion, pg_column_size or cache repair.

-- name: ProbeSignerScopeByTokenHashV1 :one
-- Existing raw BYTEA token index is not unique or constrained32. Use the paired
-- bounded CASE32 expression index; cap2 before counting and refuse ambiguity.
-- This also protects a legacy duplicate hash across two tenant documents.
WITH candidates AS MATERIALIZED (
 SELECT r.id AS recipient_id,r.document_id,d.org_id,
  CASE WHEN octet_length(r.magic_token_hash)=32 THEN r.magic_token_hash ELSE NULL::bytea END AS magic_token_hash
 FROM recipients r JOIN documents d ON d.id=r.document_id
 WHERE octet_length(sqlc.arg(token_hash)::bytea)=32 AND octet_length(r.magic_token_hash)=32
  AND (CASE WHEN octet_length(r.magic_token_hash)=32 THEN r.magic_token_hash ELSE NULL::bytea END)=sqlc.arg(token_hash)::bytea
 LIMIT 2
), candidate_count AS MATERIALIZED (SELECT count(*)::bigint AS n FROM candidates)
SELECT c.recipient_id,c.document_id,c.org_id,c.magic_token_hash FROM candidates c CROSS JOIN candidate_count n WHERE n.n=1;

-- name: GetSignerDocumentReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at,d.expires_at,
  CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('sent','in_progress','changes_requested') ELSE false END AS is_active_ceremony,
  CASE WHEN octet_length(d.status)<=17 THEN d.status='completed' ELSE false END AS is_completed_ceremony,
  (COALESCE(octet_length(d.name),0)::numeric
  +COALESCE(octet_length(d.status),0)
  +COALESCE(octet_length(d.routing_mode),0)
  +COALESCE(octet_length(d.source_kind),0)
  +COALESCE(octet_length(d.rendered_pdf_key),0)
  +COALESCE(octet_length(d.rendered_pdf_sha),0)
  +COALESCE(octet_length(d.pdf_storage_key),0)
  +COALESCE(octet_length(d.pdf_sha256),0)
  +COALESCE(octet_length(d.final_pdf_key),0)
  +COALESCE(octet_length(d.final_pdf_sha),0)
  +COALESCE(octet_length(d.audit_cert_key),0)
  +COALESCE(octet_length(d.routing_tier),0)
  +COALESCE(octet_length(d.bilingual_target_lang),0)
  +COALESCE(octet_length(d.lawful_basis),0)
  +COALESCE(octet_length(d.default_locale),0)
  +COALESCE(octet_length(d.audit_payload_key),0)
  +COALESCE(octet_length(d.audit_payload_sha256),0)
  +COALESCE(octet_length(d.audit_signature_key),0)
  +COALESCE(octet_length(d.audit_signature_sha256),0)
  +COALESCE(octet_length(d.pdf_storage_version_id),0)
  +COALESCE(octet_length(d.rendered_pdf_version_id),0)
  +COALESCE(octet_length(d.final_pdf_version_id),0)
  +COALESCE(octet_length(d.audit_cert_sha256),0)
  +COALESCE(octet_length(d.audit_cert_version_id),0)
  +COALESCE(octet_length(d.audit_payload_version_id),0)
  +COALESCE(octet_length(d.audit_signature_version_id),0)
  +COALESCE(octet_length(d.article13_notice_schema),0)
  +COALESCE(octet_length(d.html_reviewed_pdf_sha256),0)
  +COALESCE(octet_length(d.html_effective_source_commitment),0)
  +COALESCE(octet_length(d.fits_index_storage_key),0)
  +COALESCE(octet_length(d.fits_index_version_id),0)
  +COALESCE(octet_length(d.fits_index_sha256),0)
  +COALESCE(octet_length(d.signing_admission_policy),0)
  +COALESCE(octet_length(d.participant_report_schema),0))::bigint AS raw_text_bytes
 FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR SHARE OF d
), response_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.blocks_wire_bytes,m.metadata_wire_bytes,m.measurement_server_version_num
 FROM html_creation_response_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id FOR SHARE OF m
), response_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM response_cache), policy_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.html_origin_wire_bytes,m.html_current_wire_bytes,m.variables_wire_bytes,m.measurement_server_version_num
 FROM document_signing_policy_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN response_done g FOR SHARE OF m
), policy_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM policy_cache), report_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.report_wire_bytes,m.measurement_server_version_num
 FROM document_read_report_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN policy_done g FOR SHARE OF m
)
SELECT d.id,d.org_id,d.updated_at,d.expires_at,d.is_active_ceremony,d.is_completed_ceremony,d.raw_text_bytes,
 COALESCE(p.html_origin_wire_bytes,-1::bigint)::bigint AS html_origin_wire_bytes,
 COALESCE(p.html_current_wire_bytes,-1::bigint)::bigint AS html_current_wire_bytes,
 COALESCE(p.variables_wire_bytes,-1::bigint)::bigint AS variables_wire_bytes,
 COALESCE(m.blocks_wire_bytes,-1::bigint)::bigint AS blocks_wire_bytes,
 COALESCE(m.metadata_wire_bytes,-1::bigint)::bigint AS metadata_wire_bytes,
 COALESCE(r.report_wire_bytes,-1::bigint)::bigint AS report_wire_bytes,
 COALESCE(p.measurement_server_version_num,-1::integer)::integer AS policy_measurement_server_version_num,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS response_measurement_server_version_num,
 COALESCE(r.measurement_server_version_num,-1::integer)::integer AS report_measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent d LEFT JOIN response_cache m ON m.document_id=d.id AND m.org_id=d.org_id
 LEFT JOIN policy_cache p ON p.document_id=d.id AND p.org_id=d.org_id
 LEFT JOIN report_cache r ON r.document_id=d.id AND r.org_id=d.org_id;

-- name: GetSignerRecipientReadHeaderV1 :one
-- Explicit parent first even though the native caller already retains it.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,octet_length(d.status)::bigint AS doc_status_bytes FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR SHARE OF d
)
SELECT r.id AS recipient_id,r.document_id,d.org_id,
 CASE WHEN octet_length(r.magic_token_hash)=32 THEN r.magic_token_hash ELSE NULL::bytea END AS magic_token_hash,
 r.magic_token_expires_at,CASE WHEN octet_length(r.status)<=8 THEN r.status IN ('signed','accepted') ELSE false END AS is_completed_recipient,
 (octet_length(r.role)::numeric+octet_length(r.email)+octet_length(r.name)+octet_length(r.status)
  +COALESCE(octet_length(r.declined_reason),0)+octet_length(r.locale)+COALESCE(octet_length(r.magic_token_hash),0)+d.doc_status_bytes)::bigint AS raw_text_bytes
FROM recipients r JOIN parent d ON d.id=r.document_id
WHERE r.id=sqlc.arg(recipient_id)::uuid AND octet_length(sqlc.arg(token_hash)::bytea)=32
 AND (CASE WHEN octet_length(r.magic_token_hash)=32 THEN r.magic_token_hash ELSE NULL::bytea END)=sqlc.arg(token_hash)::bytea
FOR SHARE OF r;

-- name: GetSignerControllerReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR SHARE OF d
), confirmation AS MATERIALIZED (
 SELECT c.document_id,c.org_id,(octet_length(c.lawful_basis)::numeric+octet_length(c.via)+octet_length(c.controller_name)+octet_length(c.controller_contact))::bigint AS raw_text_bytes
 FROM document_lawful_basis_confirmations c JOIN parent d ON d.id=c.document_id AND d.org_id=c.org_id FOR SHARE OF c
), controller_org AS MATERIALIZED (
 SELECT o.id,(octet_length(o.name)::numeric+octet_length(o.plan)+octet_length(o.change_approval_mode))::bigint AS raw_text_bytes FROM orgs o JOIN confirmation c ON c.org_id=o.id FOR SHARE OF o
)
SELECT c.document_id,c.org_id,c.raw_text_bytes AS confirmation_raw_text_bytes,o.raw_text_bytes AS org_raw_text_bytes,
 (c.raw_text_bytes::numeric+o.raw_text_bytes)::bigint AS raw_text_bytes
FROM confirmation c JOIN controller_org o ON o.id=c.org_id;

-- name: ReadSignerDocumentV1 :one
-- The actual complete Document model is charged: all6 JSONB bodies and every33
-- current variable-width text/BYTEA field. No fabricated/sentinel source model.
SELECT d.* FROM documents d
JOIN html_creation_response_sizes_v1 m ON m.document_id=d.id AND m.org_id=d.org_id
JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
JOIN document_read_report_sizes_v1 r ON r.document_id=d.id AND r.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND p.measurement_server_version_num=current_setting('server_version_num')::integer
 AND r.measurement_server_version_num=current_setting('server_version_num')::integer
 AND p.html_origin_wire_bytes=sqlc.arg(expected_html_origin_wire_bytes)::bigint
 AND p.html_current_wire_bytes=sqlc.arg(expected_html_current_wire_bytes)::bigint
 AND p.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes)::bigint
 AND m.blocks_wire_bytes=sqlc.arg(expected_blocks_wire_bytes)::bigint
 AND m.metadata_wire_bytes=sqlc.arg(expected_metadata_wire_bytes)::bigint
 AND r.report_wire_bytes=sqlc.arg(expected_report_wire_bytes)::bigint;

-- name: ReadSignerRecipientV1 :one
SELECT r.*,d.org_id AS doc_org_id,d.status AS doc_status FROM recipients r JOIN documents d ON d.id=r.document_id
WHERE r.id=sqlc.arg(recipient_id)::uuid AND r.document_id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND octet_length(sqlc.arg(token_hash)::bytea)=32
 AND (CASE WHEN octet_length(r.magic_token_hash)=32 THEN r.magic_token_hash ELSE NULL::bytea END)=sqlc.arg(token_hash)::bytea
 AND (octet_length(r.role)::numeric+octet_length(r.email)+octet_length(r.name)+octet_length(r.status)
  +COALESCE(octet_length(r.declined_reason),0)+octet_length(r.locale)+COALESCE(octet_length(r.magic_token_hash),0)+octet_length(d.status))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: ReadSignerLawfulBasisConfirmationV1 :one
SELECT c.* FROM document_lawful_basis_confirmations c
WHERE c.document_id=sqlc.arg(document_id)::uuid AND c.org_id=sqlc.arg(org_id)::uuid
 AND (octet_length(c.lawful_basis)::numeric+octet_length(c.via)+octet_length(c.controller_name)+octet_length(c.controller_contact))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: ReadSignerControllerV1 :one
SELECT o.* FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid
 AND (octet_length(o.name)::numeric+octet_length(o.plan)+octet_length(o.change_approval_mode))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: MeasureSignerDocumentReportV1 :one
-- Only an actual fresh native producer under its retained complete report loan,
-- or a separately reviewed bounded maintenance producer, may call measurement.
-- Existing missing caches never cause on-demand expansion/recovery.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d NOWAIT
)
INSERT INTO document_read_report_sizes_v1(document_id,org_id,report_wire_bytes,measurement_server_version_num,measured_at)
SELECT d.id,d.org_id,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent d
ON CONFLICT(document_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *;

-- name: GetSignerCurrentMaterializationHeaderV1 :one
-- Parent/cache/current immutable row bind source_json to M91's exact current
-- wire measurement via canonical M74 projection guards/FKs. No JSON equality
-- or output occurs here. M75 universally constrains each retained row's report
-- wire<=65536; unlike documents.report it needs no unbounded report measurement.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.html_current_materialization_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR SHARE OF d
), policy_cache AS MATERIALIZED (
 SELECT p.document_id,p.org_id,p.html_current_wire_bytes,p.measurement_server_version_num
 FROM document_signing_policy_sizes_v1 p JOIN parent d ON d.id=p.document_id AND d.org_id=p.org_id FOR SHARE OF p
), policy_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM policy_cache), materialization AS MATERIALIZED (
 SELECT m.id,m.document_id,m.org_id,(octet_length(m.pdf_key)::numeric+octet_length(m.pdf_version_id)+octet_length(m.pdf_sha256)+octet_length(m.source_commitment)+octet_length(m.origin_commitment))::bigint AS raw_text_bytes,
  CASE WHEN m.metadata_redaction_report IS NULL THEN 0::bigint ELSE 65536::bigint END AS report_wire_upper_bound
 FROM html_document_materializations m JOIN parent d ON d.html_current_materialization_id=m.id AND d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN policy_done g FOR SHARE OF m
)
SELECT m.id AS materialization_id,m.document_id,m.org_id,m.raw_text_bytes,m.report_wire_upper_bound,
 COALESCE(p.html_current_wire_bytes,-1::bigint)::bigint AS source_wire_bytes,
 COALESCE(p.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM materialization m LEFT JOIN policy_cache p ON p.document_id=m.document_id AND p.org_id=m.org_id;

-- name: ReadSignerCurrentMaterializationV1 :one
-- Typed minimal real projection preserves EVERY Current() validation field;
-- no changed_sections array, summary, parent or attribution model is loaded.
SELECT m.id,m.document_id,m.org_id,m.sequence,m.page_count,m.pdf_key,m.pdf_version_id,m.pdf_sha256,
 m.source_commitment,m.origin_commitment,m.source_json,m.metadata_redaction_report
FROM html_document_materializations m JOIN documents d
 ON d.html_current_materialization_id=m.id AND d.id=m.document_id AND d.org_id=m.org_id
JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND m.id=sqlc.arg(expected_materialization_id)::uuid
 AND p.measurement_server_version_num=current_setting('server_version_num')::integer
 AND p.html_current_wire_bytes=sqlc.arg(expected_source_wire_bytes)::bigint
 AND (octet_length(m.pdf_key)::numeric+octet_length(m.pdf_version_id)+octet_length(m.pdf_sha256)+octet_length(m.source_commitment)+octet_length(m.origin_commitment))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint
 AND (CASE WHEN m.metadata_redaction_report IS NULL THEN 0::bigint ELSE 65536::bigint END)=sqlc.arg(expected_report_wire_upper_bound)::bigint;
