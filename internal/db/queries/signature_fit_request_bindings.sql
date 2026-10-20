-- SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
-- Private application identities/data only. No query is token/notice authority,
-- READY, physical retirement, provider retry or final-signing authorization.

-- name: GetSignatureFitRequestScopeHeaderV1 :one
-- Acquire actual metadata/work admission first. Then charge summed current raw
-- context bytes plus all input/stored-body/JSON work BEFORE hashing or payload SQL.
-- Header locks stay in the same owned application transaction through reservation.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,octet_length(d.name)::bigint AS document_name_bytes,octet_length(d.lawful_basis)::bigint AS lawful_basis_bytes,
 d.sent_at,d.article13_notice_epoch_at,d.article13_notice_schema,d.signing_admission_active_id
 FROM documents d WHERE d.id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id) AND d.signing_admission_policy='pdf-static-v1'
 AND current_setting('transaction_isolation')='read committed' FOR UPDATE OF d
), participant_count_guard AS MATERIALIZED (
 SELECT count(*)::bigint AS n FROM recipients r JOIN parent d ON d.id=r.document_id
), participant_locks AS MATERIALIZED (
 SELECT r.id FROM recipients r JOIN parent d ON d.id=r.document_id
 CROSS JOIN participant_count_guard g WHERE g.n BETWEEN 1 AND 100 ORDER BY r.id FOR UPDATE OF r
), participant_guard AS MATERIALIZED (SELECT count(*) AS n FROM participant_locks), candidate AS MATERIALIZED (
 SELECT a.id,a.org_id,a.document_id,a.ceremony_epoch,a.static_basis_sha256 FROM document_signing_admissions a JOIN parent d ON d.id=a.document_id AND d.org_id=a.org_id
 CROSS JOIN participant_guard g WHERE a.id=d.signing_admission_active_id AND g.n BETWEEN 1 AND 100 FOR UPDATE OF a
), controller AS MATERIALIZED (
 SELECT c.document_id,c.org_id,octet_length(c.controller_name)::bigint AS controller_name_bytes,octet_length(c.controller_contact)::bigint AS controller_contact_bytes,
 octet_length(c.lawful_basis)::bigint AS confirmation_basis_bytes,octet_length(c.via)::bigint AS confirmation_via_bytes
 FROM document_lawful_basis_confirmations c JOIN candidate a ON a.document_id=c.document_id AND a.org_id=c.org_id FOR SHARE OF c
), controller_org AS MATERIALIZED (
 SELECT o.id,octet_length(o.name)::bigint AS controller_org_name_bytes FROM orgs o JOIN controller c ON c.org_id=o.id FOR SHARE OF o
)
SELECT a.id AS admission_id,a.org_id,a.document_id,a.ceremony_epoch,a.static_basis_sha256,d.document_name_bytes,d.lawful_basis_bytes,
 c.controller_name_bytes,c.controller_contact_bytes,c.confirmation_basis_bytes,c.confirmation_via_bytes,o.controller_org_name_bytes,
 (d.document_name_bytes::numeric+d.lawful_basis_bytes+c.controller_name_bytes+c.controller_contact_bytes+c.confirmation_basis_bytes+c.confirmation_via_bytes+o.controller_org_name_bytes+8192)::bigint AS current_context_processing_bytes
FROM candidate a JOIN parent d ON d.id=a.document_id JOIN controller c ON c.document_id=a.document_id JOIN controller_org o ON o.id=a.org_id;

-- name: GetSignatureFitRequestBindingMetadataV1 :one
-- Cheap bounded scalar header for authenticated recovery. Recorded server/session
-- identity must be observed by the fixed same-credential independent observer;
-- rowlocks, creator XID, wall time and this row do not prove physical retirement.
SELECT preparation_id,org_id,document_id,recipient_id,ceremony_epoch,admission_id,static_basis_sha256,authority_sha256,
 original_request_sha256,original_request_bytes,accepted_intent_sha256,accepted_intent_semantic_sha256,accepted_intent_bytes,binding_sha256,captured_at,captured_transaction_id,
 creator_backend_pid,creator_backend_start,creator_database_oid,creator_user_oid,creator_server_address,creator_server_port,creator_postmaster_start FROM signature_fit_request_bindings
WHERE preparation_id=sqlc.arg(preparation_id) AND org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id) AND recipient_id=sqlc.arg(recipient_id);

-- name: FindSignatureFitRequestBindingByIntentV1 :one
-- Stable closed-v1 semantic digest excludes origin/credential/expiry/owner/key.
-- A hit requires actual full original+intent+authority+span byte comparisons and
-- private current credential rebind; it is not authorization or new admission.
SELECT preparation_id,org_id,document_id,recipient_id,ceremony_epoch,admission_id,static_basis_sha256,authority_sha256,
 original_request_sha256,original_request_bytes,accepted_intent_sha256,accepted_intent_semantic_sha256,accepted_intent_bytes,binding_sha256,captured_at,captured_transaction_id,
 creator_backend_pid,creator_backend_start,creator_database_oid,creator_user_oid,creator_server_address,creator_server_port,creator_postmaster_start FROM signature_fit_request_bindings
WHERE org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id) AND recipient_id=sqlc.arg(recipient_id)
 AND ceremony_epoch=sqlc.arg(ceremony_epoch) AND admission_id=sqlc.arg(admission_id) AND static_basis_sha256=sqlc.arg(static_basis_sha256)
 AND authority_sha256=sqlc.arg(authority_sha256) AND accepted_intent_semantic_sha256=sqlc.arg(accepted_intent_semantic_sha256);

-- name: ReadSignatureFitOriginalRequestBodyV1 :one
-- Hold actual body/DB/process loan before this BYTEA read, decode or any clone;
-- retain it through physical session CleanupDone/observer retirement.
SELECT original_request_payload FROM signature_fit_request_bindings WHERE preparation_id=sqlc.arg(preparation_id)
 AND org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id) AND recipient_id=sqlc.arg(recipient_id)
 AND binding_sha256=sqlc.arg(binding_sha256) AND original_request_sha256=sqlc.arg(expected_sha256) AND original_request_bytes=sqlc.arg(expected_bytes)
 AND original_request_bytes BETWEEN 1 AND 1048576;

-- name: ReadSignatureFitAcceptedIntentBodyV1 :one
SELECT accepted_intent_payload FROM signature_fit_request_bindings WHERE preparation_id=sqlc.arg(preparation_id)
 AND org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id) AND recipient_id=sqlc.arg(recipient_id)
 AND binding_sha256=sqlc.arg(binding_sha256) AND accepted_intent_sha256=sqlc.arg(expected_sha256) AND accepted_intent_bytes=sqlc.arg(expected_bytes)
 AND accepted_intent_bytes BETWEEN 1 AND 1048576;

-- name: ReserveBoundSignatureFitRequestV1 :one
-- ONE actual owned transaction: server UUID85 + exact87authority/span + immutable90
-- origin/intent +88designation, with existing89deriveddebt/batch/globaltenant quotas.
-- The caller must keep original private credential/notice/current candidate checks,
-- real before-dispatch admission, final credential recheck immediately pre-COMMIT,
-- and acknowledgment/unknown/physical retirement handling outside this query.
-- Existing-body comparisons and all SQL hash/JSON work need their own actual loan.
-- No provider I/O before acknowledged commit+retirement; never blindly replay an
-- unknown mutation or choose a replacement ID. First-capture context drift refuses.
SELECT preparation_id,org_id,document_id,recipient_id,ceremony_epoch,admission_id,static_basis_sha256,authority_sha256,
 original_request_sha256,original_request_bytes,accepted_intent_sha256,accepted_intent_semantic_sha256,accepted_intent_bytes,binding_sha256,captured_at,captured_transaction_id,
 creator_backend_pid,creator_backend_start,creator_database_oid,creator_user_oid,creator_server_address,creator_server_port,creator_postmaster_start
FROM hash_signature_fit_reserve_bound_request_v1(sqlc.arg(org_id)::uuid,sqlc.arg(document_id)::uuid,sqlc.arg(recipient_id)::uuid,sqlc.arg(admission_id)::uuid,
 sqlc.arg(reviewed_basis_sha256)::bytea,sqlc.arg(lease_owner_id)::uuid,sqlc.arg(lease_until)::timestamptz,
 sqlc.arg(original_request_payload)::bytea,sqlc.arg(accepted_intent_payload)::bytea,sqlc.arg(authority_payload)::bytea,sqlc.arg(span_payload)::bytea);
