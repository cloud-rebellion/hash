-- Explicit policy only. All reads/writes are scoped; original bodies are
-- separate from metadata and require caller global resource admission first.
-- READ COMMITTED parent->recipients->admission->slot->85-operation order.
-- Neither a hash nor a lease substitutes for the original signer credential.

-- name: EnablePDFSigningAdmissionPolicyV1 :one
UPDATE documents d SET signing_admission_policy='pdf-static-v1'
WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id) AND d.deleted_at IS NULL
 AND d.signing_admission_policy='historical' AND d.status IN('sent','in_progress')
 AND d.source_kind='pdf' AND d.requires_signature AND NOT d.is_envelope AND d.parent_envelope_id IS NULL
 AND d.evidence_version_pins_required AND d.article13_notice_epoch_v61_committed
 AND d.sent_at=d.article13_notice_epoch_at AND current_setting('transaction_isolation')='read committed'
 AND NOT EXISTS(SELECT 1 FROM signatures sg WHERE sg.document_id=d.id)
RETURNING d.id,d.org_id,d.signing_admission_policy;

-- name: CapturePDFSigningAdmissionV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), participant_locks AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR UPDATE OF r
), participant_guard AS MATERIALIZED (SELECT count(*) AS n FROM participant_locks)
INSERT INTO document_signing_admissions(
 id,org_id,document_id,ceremony_epoch,original_document_name,source_storage_key,source_version_id,source_sha256,source_bytes,source_pages,
 static_basis_payload,static_basis_sha256,static_basis_body_sha256,geometry_payload,geometry_payload_sha256,geometry_pages_payload,geometry_sha256,
 fields_payload,fields_sha256,parties_payload,parties_sha256,render_recipe_payload,render_recipe_sha256,ordinary_recipe_payload,ordinary_recipe_sha256,branding_context_sha256,
 expected_ordinary_pages,required_parties,field_count,base_bytes_limit,descriptor_bytes_limit,final_pdf_bytes_limit,fits_index_bytes_limit,
 certificate_pdf_bytes_limit,certificate_payload_bytes_limit,certificate_signature_bytes_limit,events_bytes_limit,versions_bytes_limit,archive_manifest_bytes_limit,
 archive_budget_bytes,processing_budget_bytes,owner_id,lease_until
)
SELECT sqlc.arg(id),d.org_id,d.id,sqlc.arg(ceremony_epoch),sqlc.arg(original_document_name),sqlc.arg(source_storage_key),sqlc.arg(source_version_id),
 sqlc.arg(source_sha256),sqlc.arg(source_bytes),sqlc.arg(source_pages),sqlc.arg(static_basis_payload),sqlc.arg(static_basis_sha256),sqlc.arg(static_basis_body_sha256),
 sqlc.arg(geometry_payload),sqlc.arg(geometry_payload_sha256),sqlc.arg(geometry_pages_payload),sqlc.arg(geometry_sha256),sqlc.arg(fields_payload),sqlc.arg(fields_sha256),
 sqlc.arg(parties_payload),sqlc.arg(parties_sha256),sqlc.arg(render_recipe_payload),sqlc.arg(render_recipe_sha256),sqlc.arg(ordinary_recipe_payload),sqlc.arg(ordinary_recipe_sha256),
 sqlc.arg(branding_context_sha256),sqlc.arg(expected_ordinary_pages),sqlc.arg(required_parties),sqlc.arg(field_count),sqlc.arg(base_bytes_limit),sqlc.arg(descriptor_bytes_limit),
 sqlc.arg(final_pdf_bytes_limit),sqlc.arg(fits_index_bytes_limit),sqlc.arg(certificate_pdf_bytes_limit),sqlc.arg(certificate_payload_bytes_limit),sqlc.arg(certificate_signature_bytes_limit),
 sqlc.arg(events_bytes_limit),sqlc.arg(versions_bytes_limit),sqlc.arg(archive_manifest_bytes_limit),sqlc.arg(archive_budget_bytes),sqlc.arg(processing_budget_bytes),sqlc.arg(owner_id),sqlc.arg(lease_until)
FROM parent d CROSS JOIN participant_guard g WHERE g.n BETWEEN 1 AND 100
RETURNING id,org_id,document_id,ceremony_epoch,static_basis_sha256,static_basis_body_sha256,
 octet_length(static_basis_payload)::bigint AS static_basis_bytes,status,owner_id,lease_until;

-- name: ActivatePDFSigningAdmissionCandidateV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), candidate AS MATERIALIZED (
 SELECT a.id FROM document_signing_admissions a JOIN parent d ON d.id=a.document_id AND d.org_id=a.org_id
 WHERE a.id=sqlc.arg(admission_id) AND a.static_basis_sha256=sqlc.arg(static_basis_sha256) AND a.status IN('staging','ready') FOR UPDATE OF a
)
UPDATE documents d SET signing_admission_active_id=a.id FROM candidate a WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND d.signing_admission_sealed_id IS NULL AND NOT EXISTS(SELECT 1 FROM signatures WHERE document_id=d.id)
RETURNING d.id,d.org_id,d.signing_admission_active_id;

-- name: GetPDFSigningAdmissionCandidateMetadataV1 :one
-- Only the exact current active/sealed candidate reuses its SHA. A stale
-- incarnation is readable by exact old ID, never revived or adopted by SHA.
SELECT a.id,a.org_id,a.document_id,a.ceremony_epoch,a.static_basis_sha256,a.static_basis_body_sha256,
 octet_length(a.static_basis_payload)::bigint AS static_basis_bytes,a.status,a.owner_id,a.lease_until,a.ready_at,a.sealed_at,a.stale_at
FROM document_signing_admissions a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
WHERE a.document_id=sqlc.arg(document_id) AND a.org_id=sqlc.arg(org_id)
 AND a.ceremony_epoch=sqlc.arg(ceremony_epoch) AND a.static_basis_sha256=sqlc.arg(static_basis_sha256)
 AND a.status IN('staging','ready','sealed') AND (a.id=d.signing_admission_active_id OR a.id=d.signing_admission_sealed_id);

-- name: ListPDFSigningAdmissionSlotsMetadataV1 :many
SELECT sl.admission_id,sl.org_id,sl.document_id,sl.recipient_id,sl.target_ids,sl.occupied_pages,
 sl.target_count,sl.page_count,sl.expected_objects,sl.fit_bytes_limit,sl.pdf_bytes_limit,sl.designated_preparation_id,sl.designated_owner_id
FROM document_signing_admission_slots sl
WHERE sl.admission_id=sqlc.arg(admission_id) AND sl.org_id=sqlc.arg(org_id) AND sl.document_id=sqlc.arg(document_id)
ORDER BY sl.recipient_id LIMIT 101;

-- name: ClaimPDFSigningAdmissionLeaseV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
)
UPDATE document_signing_admissions a SET owner_id=sqlc.arg(owner_id),lease_until=sqlc.arg(lease_until),attempts=a.attempts+1,updated_at=clock_timestamp()
FROM parent d WHERE a.id=sqlc.arg(admission_id) AND a.document_id=d.id AND a.org_id=d.org_id
 AND a.status IN('staging','ready') AND a.lease_until<=clock_timestamp() AND a.attempts<8 AND sqlc.arg(lease_until)::timestamptz>clock_timestamp()
RETURNING a.id,a.org_id,a.document_id,a.status,a.owner_id,a.lease_until,a.attempts;

-- name: CapturePDFSigningAdmissionBodyV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), participant_locks AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR UPDATE OF r
), participant_guard AS MATERIALIZED (SELECT count(*) AS n FROM participant_locks),
 operation AS MATERIALIZED (
 SELECT a.id,a.org_id,a.document_id FROM document_signing_admissions a JOIN parent d ON d.id=a.document_id AND d.org_id=a.org_id CROSS JOIN participant_guard g
 WHERE a.id=sqlc.arg(admission_id) AND a.owner_id=sqlc.arg(owner_id) AND a.status='staging' AND a.lease_until>clock_timestamp() AND g.n BETWEEN 1 AND 100 FOR UPDATE OF a
)
INSERT INTO document_signing_admission_bodies(admission_id,org_id,document_id,kind,page,payload,sha256,bytes,content_type,
 static_basis_sha256,plan_payload,plan_sha256,package_sha256,report_sha256,inspection_sha256,captured_owner_id)
SELECT a.id,a.org_id,a.document_id,'ordinary_page',sqlc.arg(page),sqlc.arg(payload),sqlc.arg(sha256),sqlc.arg(bytes),'application/pdf',
 sqlc.arg(static_basis_sha256),sqlc.arg(plan_payload),sqlc.arg(plan_sha256),sqlc.arg(package_sha256),sqlc.arg(report_sha256),sqlc.arg(inspection_sha256),sqlc.arg(owner_id)
FROM operation a RETURNING admission_id,org_id,document_id,kind,page,sha256,bytes,content_type,static_basis_sha256,
 plan_sha256,octet_length(plan_payload)::bigint AS plan_bytes,package_sha256,report_sha256,inspection_sha256,captured_owner_id,captured_at;

-- name: ListPDFSigningAdmissionBodyMetadataV1 :many
SELECT b.admission_id,b.org_id,b.document_id,b.kind,b.page,b.sha256,b.bytes,b.content_type,b.static_basis_sha256,b.plan_sha256,
 octet_length(b.plan_payload)::bigint AS plan_bytes,b.package_sha256,b.report_sha256,b.inspection_sha256,b.captured_owner_id,b.captured_at
FROM document_signing_admission_bodies b
WHERE b.admission_id=sqlc.arg(admission_id) AND b.org_id=sqlc.arg(org_id) AND b.document_id=sqlc.arg(document_id)
ORDER BY b.page LIMIT 501;

-- name: ReadPDFSigningAdmissionBodyV1 :one
SELECT b.payload FROM document_signing_admission_bodies b
WHERE b.admission_id=sqlc.arg(admission_id) AND b.org_id=sqlc.arg(org_id) AND b.document_id=sqlc.arg(document_id) AND b.kind='ordinary_page' AND b.page=sqlc.arg(page)
 AND b.sha256=sqlc.arg(expected_sha256) AND b.bytes=sqlc.arg(expected_bytes) AND b.bytes BETWEEN 1 AND 8388608;

-- name: ReadPDFSigningAdmissionPlanV1 :one
SELECT b.plan_payload FROM document_signing_admission_bodies b
WHERE b.admission_id=sqlc.arg(admission_id) AND b.org_id=sqlc.arg(org_id) AND b.document_id=sqlc.arg(document_id) AND b.kind='ordinary_page' AND b.page=sqlc.arg(page)
 AND b.plan_sha256=sqlc.arg(expected_sha256) AND octet_length(b.plan_payload)::bigint=sqlc.arg(expected_bytes)::bigint
 AND octet_length(b.plan_payload) BETWEEN 1 AND 1048576;

-- name: ReadPDFSigningAdmissionBasisV1 :one
SELECT a.static_basis_payload FROM document_signing_admissions a
WHERE a.id=sqlc.arg(admission_id) AND a.org_id=sqlc.arg(org_id) AND a.document_id=sqlc.arg(document_id)
 AND a.static_basis_sha256=sqlc.arg(static_basis_sha256) AND a.static_basis_body_sha256=sqlc.arg(expected_sha256)
 AND octet_length(a.static_basis_payload)::bigint=sqlc.arg(expected_bytes)::bigint AND octet_length(a.static_basis_payload) BETWEEN 1 AND 4194304;

-- name: MarkPDFSigningAdmissionReadyV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), participant_locks AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR UPDATE OF r
), participant_guard AS MATERIALIZED (SELECT count(*) AS n FROM participant_locks)
UPDATE document_signing_admissions a SET status='ready',source_inspection_sha256=sqlc.arg(source_inspection_sha256),ready_at=clock_timestamp(),updated_at=clock_timestamp()
FROM parent d CROSS JOIN participant_guard g WHERE a.id=sqlc.arg(admission_id) AND a.org_id=d.org_id AND a.document_id=d.id
 AND a.owner_id=sqlc.arg(owner_id) AND a.lease_until>clock_timestamp() AND a.status='staging' AND g.n BETWEEN 1 AND 100
RETURNING a.id,a.org_id,a.document_id,a.static_basis_sha256,a.status,a.ready_at;

-- name: DesignatePDFSigningAdmissionFitPreparationV1 :one
-- The caller inserts85+87 originals and designates in ONE actual transaction.
-- A sealed static basis allows later independent actors to prepare their own
-- actual names. It does not require the original admission owner's live lease.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), recipient_lock AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id WHERE r.id=sqlc.arg(recipient_id) AND r.status IN('pending','sent','viewed') FOR UPDATE OF r
), operation AS MATERIALIZED (
 SELECT a.id,a.org_id,a.document_id FROM document_signing_admissions a JOIN parent d ON d.id=a.document_id AND d.org_id=a.org_id
 JOIN recipient_lock r ON TRUE WHERE a.id=sqlc.arg(admission_id) AND a.status IN('staging','ready','sealed') FOR UPDATE OF a
), slot_lock AS MATERIALIZED (
 SELECT sl.admission_id,sl.recipient_id FROM document_signing_admission_slots sl JOIN operation a ON a.id=sl.admission_id
 JOIN recipient_lock r ON r.id=sl.recipient_id FOR UPDATE OF sl
)
UPDATE document_signing_admission_slots sl SET designated_preparation_id=sqlc.arg(preparation_id),designated_owner_id=sqlc.arg(owner_id)
FROM slot_lock l WHERE sl.admission_id=l.admission_id AND sl.recipient_id=l.recipient_id
RETURNING sl.admission_id,sl.org_id,sl.document_id,sl.recipient_id,sl.target_ids,sl.occupied_pages,sl.expected_objects,sl.fit_bytes_limit,sl.pdf_bytes_limit,sl.designated_preparation_id,sl.designated_owner_id;

-- name: SealAndBindPDFSigningAdmissionV1 :one
-- Caller has inserted the real fitted signature+85companion, and commits status,
-- required-index marker and exact signed_event_id audit together; final original
-- credential recheck is immediately BEFORE that caller COMMIT. No provider IO.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), recipient_lock AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id WHERE r.id=sqlc.arg(recipient_id) FOR UPDATE OF r
), admission_lock AS MATERIALIZED (
 SELECT a.id,a.status FROM document_signing_admissions a JOIN parent d ON d.id=a.document_id AND d.org_id=a.org_id
 JOIN recipient_lock r ON TRUE WHERE a.id=sqlc.arg(admission_id) AND a.static_basis_sha256=sqlc.arg(reviewed_basis_sha256)
 AND ((a.status='ready' AND a.owner_id=sqlc.arg(admission_owner_id) AND a.lease_until>clock_timestamp()) OR a.status='sealed') FOR UPDATE OF a
), sealed AS (
 UPDATE document_signing_admissions a SET status='sealed',first_signature_id=sqlc.arg(signature_id),sealed_at=clock_timestamp(),updated_at=clock_timestamp()
 FROM admission_lock l WHERE a.id=l.id AND l.status='ready' RETURNING a.id
), chosen AS MATERIALIZED (
 SELECT id FROM sealed UNION ALL SELECT id FROM admission_lock WHERE status='sealed'
), document_seal AS (
 UPDATE documents d SET signing_admission_sealed_id=c.id FROM chosen c WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
  AND d.signing_admission_active_id=c.id AND (d.signing_admission_sealed_id IS NULL OR d.signing_admission_sealed_id=c.id) RETURNING d.id,d.org_id,c.id AS admission_id
)
INSERT INTO signature_signing_admission_bindings(signature_id,admission_id,org_id,document_id,recipient_id,field_id,static_basis_sha256,reviewed_basis_sha256,selection_id,signed_event_id)
SELECT sqlc.arg(signature_id),d.admission_id,d.org_id,d.id,sqlc.arg(recipient_id),sqlc.arg(field_id),sqlc.arg(reviewed_basis_sha256),sqlc.arg(reviewed_basis_sha256),sqlc.arg(selection_id),sqlc.arg(signed_event_id)
FROM document_seal d RETURNING signature_id,admission_id,org_id,document_id,recipient_id,field_id,static_basis_sha256,selection_id,signed_event_id,bound_at;

-- name: GetPDFSigningAdmissionSignatureBindingV1 :one
SELECT b.signature_id,b.admission_id,b.org_id,b.document_id,b.recipient_id,b.field_id,b.static_basis_sha256,b.reviewed_basis_sha256,b.selection_id,b.signed_event_id,b.bound_at
FROM signature_signing_admission_bindings b WHERE b.signature_id=sqlc.arg(signature_id) AND b.org_id=sqlc.arg(org_id) AND b.document_id=sqlc.arg(document_id);


-- name: GetPDFSigningAdmissionMetadataForUpdateV1 :one
-- FULL database JSON consistency validation. Caller MUST already hold a global
-- DB/process permit sized from GetPDFSigningAdmissionHeaderMetadataForUpdateV1
-- BEFORE dispatching this query. Ready/seal/capture triggers require that same
-- admitted resource ownership. This query is not a cheap initial header read.
-- Latest lease clock is evaluated AFTER materialized parent/participant locks.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.status AS document_status,(d.deleted_at IS NOT NULL)::boolean AS document_deleted
 FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), participants AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR UPDATE OF r
), participant_guard AS MATERIALIZED (SELECT count(*) AS n FROM participants),
 operation AS MATERIALIZED (
 SELECT a.id,a.org_id,a.document_id,a.ceremony_epoch,a.source_storage_key,a.source_version_id,a.source_sha256,a.source_bytes,a.source_pages,
 a.static_basis_sha256,a.static_basis_body_sha256,octet_length(a.static_basis_payload)::bigint AS static_basis_bytes,
 a.geometry_payload_sha256,octet_length(a.geometry_payload)::bigint AS geometry_bytes,a.geometry_sha256,octet_length(a.geometry_pages_payload)::bigint AS geometry_pages_bytes,
 a.fields_sha256,octet_length(a.fields_payload)::bigint AS fields_bytes,a.parties_sha256,octet_length(a.parties_payload)::bigint AS parties_bytes,
 a.render_recipe_sha256,octet_length(a.render_recipe_payload)::bigint AS render_recipe_bytes,
 a.ordinary_recipe_sha256,octet_length(a.ordinary_recipe_payload)::bigint AS ordinary_recipe_bytes,a.branding_context_sha256,
 a.expected_ordinary_pages,a.required_parties,a.field_count,a.base_bytes_limit,a.descriptor_bytes_limit,a.final_pdf_bytes_limit,a.fits_index_bytes_limit,
 a.certificate_pdf_bytes_limit,a.certificate_payload_bytes_limit,a.certificate_signature_bytes_limit,a.events_bytes_limit,a.versions_bytes_limit,a.archive_manifest_bytes_limit,
 a.archive_budget_bytes,a.processing_budget_bytes,a.source_inspection_sha256,a.ready_at,a.sealed_at,a.stale_at,a.first_signature_id,
 a.owner_id,a.lease_until,a.attempts,a.status,p.document_status,p.document_deleted
 FROM document_signing_admissions a JOIN parent p ON p.id=a.document_id AND p.org_id=a.org_id CROSS JOIN participant_guard g
 WHERE a.id=sqlc.arg(admission_id) AND (a.owner_id=sqlc.arg(owner_id) OR a.status='sealed') AND g.n BETWEEN 1 AND 100 FOR UPDATE OF a
)
SELECT operation.*,(operation.lease_until>clock_timestamp())::boolean AS lease_current,(operation.owner_id=sqlc.arg(owner_id)::uuid)::boolean AS owner_matches,
 hash_pdf_admission_current_matches_v1(operation.id,operation.org_id,operation.document_id)::boolean AS current_basis
FROM operation;

-- name: ReadPDFSigningAdmissionComponentV1 :one
-- Require exact metadata hash/length and global resource permit BEFORE invoking.
SELECT (CASE sqlc.arg(kind)::text
 WHEN 'geometry' THEN a.geometry_payload WHEN 'geometry_pages' THEN a.geometry_pages_payload
 WHEN 'fields' THEN a.fields_payload WHEN 'parties' THEN a.parties_payload
 WHEN 'render_recipe' THEN a.render_recipe_payload WHEN 'ordinary_recipe' THEN a.ordinary_recipe_payload END)::bytea AS payload
FROM document_signing_admissions a
WHERE a.id=sqlc.arg(admission_id) AND a.org_id=sqlc.arg(org_id) AND a.document_id=sqlc.arg(document_id)
 AND CASE sqlc.arg(kind)::text
 WHEN 'geometry' THEN a.geometry_payload_sha256 WHEN 'geometry_pages' THEN a.geometry_sha256
 WHEN 'fields' THEN a.fields_sha256 WHEN 'parties' THEN a.parties_sha256
 WHEN 'render_recipe' THEN a.render_recipe_sha256 WHEN 'ordinary_recipe' THEN a.ordinary_recipe_sha256 END=sqlc.arg(expected_sha256)
 AND CASE sqlc.arg(kind)::text
 WHEN 'geometry' THEN octet_length(a.geometry_payload)::bigint WHEN 'geometry_pages' THEN octet_length(a.geometry_pages_payload)::bigint
 WHEN 'fields' THEN octet_length(a.fields_payload)::bigint WHEN 'parties' THEN octet_length(a.parties_payload)::bigint
 WHEN 'render_recipe' THEN octet_length(a.render_recipe_payload)::bigint WHEN 'ordinary_recipe' THEN octet_length(a.ordinary_recipe_payload)::bigint END=sqlc.arg(expected_bytes)::bigint
 AND sqlc.arg(expected_bytes)::bigint BETWEEN 1 AND 1048576;

-- name: ListPDFSigningAdmissionSignatureBindingsV1 :many
SELECT b.signature_id,b.admission_id,b.org_id,b.document_id,b.recipient_id,b.field_id,b.static_basis_sha256,b.reviewed_basis_sha256,b.selection_id,b.signed_event_id,b.bound_at
FROM signature_signing_admission_bindings b
WHERE b.admission_id=sqlc.arg(admission_id) AND b.org_id=sqlc.arg(org_id) AND b.document_id=sqlc.arg(document_id)
ORDER BY b.signature_id LIMIT 101;

-- name: GetPDFSigningAdmissionHeaderMetadataForUpdateV1 :one
-- BODY-FREE initial admission: no JSON decoding/current-basis helper. Obtain
-- the global DB/process permit from these bytecounts BEFORE validating JSON,
-- body copies, or ready/seal/capture triggers. While holding locks, admission
-- must be NONBLOCKING. Otherwise rollback/release locks, acquire resources,
-- then open/lock/recheck the fresh header; never invert quota/doc lock order.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.status AS document_status,(d.deleted_at IS NOT NULL)::boolean AS document_deleted,
 d.source_kind,d.requires_signature,d.is_envelope,d.parent_envelope_id,d.sent_at,d.article13_notice_epoch_at,d.article13_notice_epoch_v61_committed,
 d.pdf_storage_key,d.pdf_storage_version_id,d.pdf_sha256,d.signing_admission_policy,d.signing_admission_active_id,d.signing_admission_sealed_id,
 d.signature_fit_reserved_bytes,d.signing_admission_count,d.signing_admission_static_bytes,d.signing_admission_ordinary_bytes,d.signing_admission_plan_bytes
 FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id)
 AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), participants AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id ORDER BY r.id FOR UPDATE OF r
), participant_guard AS MATERIALIZED (SELECT count(*) AS n FROM participants),
 operation AS MATERIALIZED (
 SELECT a.id,a.org_id,a.document_id,a.ceremony_epoch,a.source_storage_key,a.source_version_id,a.source_sha256,a.source_bytes,a.source_pages,
 a.static_basis_sha256,a.static_basis_body_sha256,octet_length(a.static_basis_payload)::bigint AS static_basis_bytes,
 a.geometry_payload_sha256,octet_length(a.geometry_payload)::bigint AS geometry_bytes,a.geometry_sha256,octet_length(a.geometry_pages_payload)::bigint AS geometry_pages_bytes,
 a.fields_sha256,octet_length(a.fields_payload)::bigint AS fields_bytes,a.parties_sha256,octet_length(a.parties_payload)::bigint AS parties_bytes,
 a.render_recipe_sha256,octet_length(a.render_recipe_payload)::bigint AS render_recipe_bytes,
 a.ordinary_recipe_sha256,octet_length(a.ordinary_recipe_payload)::bigint AS ordinary_recipe_bytes,a.branding_context_sha256,
 a.expected_ordinary_pages,a.required_parties,a.field_count,a.base_bytes_limit,a.descriptor_bytes_limit,a.final_pdf_bytes_limit,a.fits_index_bytes_limit,
 a.certificate_pdf_bytes_limit,a.certificate_payload_bytes_limit,a.certificate_signature_bytes_limit,a.events_bytes_limit,a.versions_bytes_limit,a.archive_manifest_bytes_limit,
 a.archive_budget_bytes,a.processing_budget_bytes,a.source_inspection_sha256,a.ready_at,a.sealed_at,a.stale_at,a.first_signature_id,
 a.owner_id,a.lease_until,a.attempts,a.status,p.document_status,p.document_deleted,
 p.signature_fit_reserved_bytes,p.signing_admission_count,p.signing_admission_static_bytes,p.signing_admission_ordinary_bytes,p.signing_admission_plan_bytes,
 COALESCE(p.source_kind='pdf' AND p.requires_signature AND NOT p.is_envelope AND p.parent_envelope_id IS NULL
  AND p.signing_admission_policy='pdf-static-v1' AND p.article13_notice_epoch_v61_committed
  AND ROW(p.sent_at,p.article13_notice_epoch_at,p.pdf_storage_key,p.pdf_storage_version_id,p.pdf_sha256)
   IS NOT DISTINCT FROM ROW(a.ceremony_epoch,a.ceremony_epoch,a.source_storage_key,a.source_version_id,a.source_sha256)
  AND (p.signing_admission_active_id=a.id OR p.signing_admission_sealed_id=a.id),FALSE)::boolean AS current_document_identity
 FROM document_signing_admissions a JOIN parent p ON p.id=a.document_id AND p.org_id=a.org_id CROSS JOIN participant_guard g
 WHERE a.id=sqlc.arg(admission_id) AND (a.owner_id=sqlc.arg(owner_id) OR a.status='sealed') AND g.n BETWEEN 1 AND 100 FOR UPDATE OF a
)
SELECT operation.*,(operation.lease_until>clock_timestamp())::boolean AS lease_current,(operation.owner_id=sqlc.arg(owner_id)::uuid)::boolean AS owner_matches
FROM operation;
