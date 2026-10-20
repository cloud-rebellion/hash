-- SOURCE-ONLY M94 foundation. Same genuine owned session/transaction, original
-- identity/policy and live authorization are mandatory application gates. No
-- missing/stale cache row grants measurement, retry, backfill or activation.

-- name: GetDocumentAIReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at,d.expires_at,d.sender_id,
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
SELECT d.id,d.org_id,d.updated_at,d.expires_at,d.sender_id,d.is_draft,d.is_changes_requested,d.has_html_source,d.is_active_ceremony,d.is_completed_ceremony,d.raw_text_bytes,
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


-- Scalar discovery is not authorization. The genuine native writer locks the
-- actual physical root before its actual target/actor reader.
-- name: GetDocumentAIRootV1 :one
SELECT r.id FROM documents d JOIN documents r
 ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL;

-- name: LockDocumentAIRootV1 :one
SELECT r.id AS root_document_id,r.is_envelope,(r.parent_envelope_id IS NOT NULL)::boolean AS root_has_parent FROM documents r
WHERE r.id=sqlc.arg(root_document_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
 AND r.deleted_at IS NULL
FOR SHARE OF r;

-- Fresh statement after the possible root wait; no automatic scope retry.
-- name: DocumentAIRootMatchesV1 :one
SELECT EXISTS(SELECT 1 FROM documents d JOIN documents r
 ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND r.id=sqlc.arg(root_document_id)::uuid
 AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL
 AND (d.id=r.id OR r.is_envelope));

-- Both document locks precede these fixed scalar facts. Status refusals stay
-- after the original member/credential and organization privacy-fence stages.
-- name: GetDocumentAIPolicyV1 :one
SELECT r.id AS root_document_id,d.id AS document_id,
 CASE WHEN octet_length(r.status)<=17 THEN r.status='draft' ELSE false END AS root_draft,
 CASE WHEN octet_length(d.status)<=17 THEN d.status='draft' ELSE false END AS document_draft,
 CASE WHEN octet_length(r.status)<=17 THEN r.status IN ('draft','sent','in_progress','changes_requested') ELSE false END AS root_allowed,
 CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('draft','sent','in_progress','changes_requested') ELSE false END AS document_allowed
FROM documents d JOIN documents r ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND r.id=sqlc.arg(root_document_id)::uuid
 AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL;


-- Cheap scalar text lengths precede full actual usage projection. This query
-- cannot authorize provider dispatch; only the private committed request can.
-- name: GetDocumentAIUsageHeaderV1 :one
SELECT a.id,a.org_id,a.document_id,a.actor_user_id,a.created_at,
 (octet_length(a.provider)::numeric+octet_length(a.model)+octet_length(a.prompt_name)
 +octet_length(a.error)+octet_length(a.transfer_jurisdiction))::bigint AS raw_text_bytes
FROM ai_completion_audit a
WHERE a.id=sqlc.arg(request_event_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid
 AND a.document_id=sqlc.arg(document_id)::uuid AND a.actor_user_id=sqlc.arg(actor_user_id)::uuid
FOR SHARE OF a;

-- name: ReadDocumentAIUsageV1 :one
SELECT a.* FROM ai_completion_audit a
WHERE a.id=sqlc.arg(request_event_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid
 AND a.document_id=sqlc.arg(document_id)::uuid AND a.actor_user_id=sqlc.arg(actor_user_id)::uuid
 AND a.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND (octet_length(a.provider)::numeric+octet_length(a.model)+octet_length(a.prompt_name)
 +octet_length(a.error)+octet_length(a.transfer_jurisdiction))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;
