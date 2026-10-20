-- Purpose-bound, original unlocked PDF layout pre-inspection. No parent/cache
-- lock crosses provider/isolated PageCount work. Every full Document is admitted
-- from actual M91/M92/M93, source stamp and true raw TEXT/BYTEA scalar before
-- expansion, then the original later locked draft guard rechecks source/CAS.
-- No measurement, repair, caller source/Tx or signing-stage authority exists.

-- name: GetPDFLayoutInspectionSourceHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at,d.expires_at,d.sender_id,
  (d.source_kind='pdf')::boolean AS is_pdf_source,
  (d.pdf_storage_key IS NOT NULL AND COALESCE(octet_length(d.pdf_sha256),0)=32)::boolean AS has_verified_pdf_commitment,
  CASE WHEN octet_length(d.status)<=17 THEN d.status='draft' ELSE false END AS is_draft,
  CASE WHEN octet_length(d.status)<=17 THEN d.status='changes_requested' ELSE false END AS is_changes_requested,
  (d.html_source_json IS NOT NULL)::boolean AS has_html_source,
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
  AND d.deleted_at IS NULL
), response_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.blocks_wire_bytes,m.metadata_wire_bytes,m.measurement_server_version_num
 FROM html_creation_response_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
), response_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM response_cache), policy_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.html_origin_wire_bytes,m.html_current_wire_bytes,m.variables_wire_bytes,m.measurement_server_version_num
 FROM document_signing_policy_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN response_done g
), policy_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM policy_cache), report_cache AS MATERIALIZED (
 SELECT m.document_id,m.org_id,m.report_wire_bytes,m.measurement_server_version_num
 FROM document_read_report_sizes_v1 m JOIN parent d ON d.id=m.document_id AND d.org_id=m.org_id
 CROSS JOIN policy_done g
)
SELECT d.id,d.org_id,d.updated_at,d.expires_at,d.sender_id,d.is_pdf_source,d.has_verified_pdf_commitment,d.is_draft,d.is_changes_requested,d.has_html_source,d.is_active_ceremony,d.is_completed_ceremony,d.raw_text_bytes,
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

-- name: ReadPDFLayoutInspectionDocumentV1 :one
-- The actual complete Document model is charged: all6 JSONB bodies and every33
-- current variable-width text/BYTEA field. No fabricated/sentinel source model.
SELECT d.* FROM documents d
JOIN html_creation_response_sizes_v1 m ON m.document_id=d.id AND m.org_id=d.org_id
JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
JOIN document_read_report_sizes_v1 r ON r.document_id=d.id AND r.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND d.source_kind='pdf' AND d.status='draft' AND d.html_source_json IS NULL
 AND (COALESCE(octet_length(d.name),0)::numeric
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
  +COALESCE(octet_length(d.participant_report_schema),0))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND p.measurement_server_version_num=current_setting('server_version_num')::integer
 AND r.measurement_server_version_num=current_setting('server_version_num')::integer
 AND p.html_origin_wire_bytes=sqlc.arg(expected_html_origin_wire_bytes)::bigint
 AND p.html_current_wire_bytes=sqlc.arg(expected_html_current_wire_bytes)::bigint
 AND p.variables_wire_bytes=sqlc.arg(expected_variables_wire_bytes)::bigint
 AND m.blocks_wire_bytes=sqlc.arg(expected_blocks_wire_bytes)::bigint
 AND m.metadata_wire_bytes=sqlc.arg(expected_metadata_wire_bytes)::bigint
 AND r.report_wire_bytes=sqlc.arg(expected_report_wire_bytes)::bigint;
