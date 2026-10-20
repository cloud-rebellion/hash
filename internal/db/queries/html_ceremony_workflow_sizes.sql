-- Actual workflow scalar/read projections. A genuine native owner retains the
-- SAME parent UPDATE and original credential/state policy before body queries.
-- These queries confer no actor, ceremony, cache, mutation or work authority.

-- name: HasCapturedHTMLCeremonyEvidenceV1 :one
-- Exact revisionHasCapturedEvidence truth without full recipients/signatures/
-- fields bodies. Nullness retains the original pgtype.Valid behavior (including
-- empty TEXT and infinite timestamps). No collection/history is truncated.
WITH parent AS MATERIALIZED (
 SELECT d.id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d
)
SELECT (EXISTS(SELECT 1 FROM recipients r WHERE r.document_id=d.id AND
  ((CASE WHEN octet_length(r.status)<=8 THEN r.status IN('signed','accepted') ELSE false END) OR r.signed_at IS NOT NULL))
 OR EXISTS(SELECT 1 FROM signatures s WHERE s.document_id=d.id)
 OR EXISTS(SELECT 1 FROM document_fields f WHERE f.document_id=d.id AND (f.value IS NOT NULL OR f.completed_at IS NOT NULL)))::boolean AS has_captured_evidence
FROM parent d;

-- name: GetHTMLChangeRequestReadHeaderV1 :one
-- Caller performs ORIGINAL live actor/credential and parent-state decisions
-- before invoking this CR stage. Keep parent->actual scoped request lock order.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d
), request AS MATERIALIZED (
 SELECT cr.id,cr.document_id,
  (CASE WHEN octet_length(cr.status)<=8 THEN cr.status='open' ELSE false END)::boolean AS is_open,
  (octet_length(cr.message)::numeric+octet_length(cr.status)+octet_length(cr.block_id)
   +octet_length(cr.quote)+octet_length(cr.context)+octet_length(cr.proposed)
   +COALESCE(octet_length(cr.resolution),0))::bigint AS raw_text_bytes
 FROM change_requests cr JOIN parent d ON d.id=cr.document_id
 WHERE cr.id=sqlc.arg(change_request_id)::uuid FOR UPDATE OF cr
)
SELECT cr.id AS change_request_id,cr.document_id,d.org_id,cr.is_open,cr.raw_text_bytes
FROM request cr JOIN parent d ON d.id=cr.document_id;

-- name: ReadHTMLChangeRequestV1 :one
-- Full actual model only after header-derived retained raw/body loan in the
-- same owned transaction, with its exact parent/request UPDATE locks retained.
SELECT cr.* FROM change_requests cr JOIN documents d ON d.id=cr.document_id
WHERE cr.id=sqlc.arg(change_request_id)::uuid AND cr.document_id=sqlc.arg(document_id)::uuid
 AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND (octet_length(cr.message)::numeric+octet_length(cr.status)+octet_length(cr.block_id)
  +octet_length(cr.quote)+octet_length(cr.context)+octet_length(cr.proposed)
  +COALESCE(octet_length(cr.resolution),0))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: GetHTMLWorkflowOrgReadHeaderV1 :one
-- Decision mode did not require a lawful-basis confirmation; do not reuse a
-- confirmation-dependent signer header or invent a partial Org. After loan,
-- existing ReadSignerControllerV1 returns the actual full Org under same SHARE.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d
)
SELECT o.id AS org_id,d.id AS document_id,
 (octet_length(o.name)::numeric+octet_length(o.plan)+octet_length(o.change_approval_mode))::bigint AS raw_text_bytes
FROM orgs o JOIN parent d ON d.org_id=o.id FOR SHARE OF o;


-- name: GetHTMLCeremonyWorkflowAccessV1 :one
-- Fixed scalar pins for original locked notice/state/envelope decisions BEFORE
-- full source/cache body admission. Current actual Article13 registry supports
-- ONLY hash-a13-2026-08-31 (19bytes). A new registered schema requires a guarded
-- SQL source update; arbitrary input/legacy stored strings are not expanded.
SELECT d.id,d.org_id,d.updated_at,d.sent_at,d.article13_notice_epoch_at,d.expires_at,
 d.article13_notice_epoch_v61_committed,
 (CASE WHEN octet_length(d.pdf_sha256)=32 THEN d.pdf_sha256 ELSE NULL::bytea END)::bytea AS pdf_sha256,
 (octet_length(d.name)::numeric+octet_length(d.lawful_basis)+octet_length(d.article13_notice_schema))::bigint AS policy_raw_text_bytes,
 (CASE WHEN octet_length(d.status)<=17 THEN d.status IN('sent','in_progress','changes_requested') ELSE false END)::boolean AS is_active_ceremony,
 d.is_envelope,d.parent_envelope_id,
 (CASE WHEN octet_length(sqlc.arg(expected_notice_schema)::text)=19 AND octet_length(d.article13_notice_schema)=19
  THEN CASE WHEN sqlc.arg(expected_notice_schema)::text='hash-a13-2026-08-31'
   THEN d.article13_notice_schema=sqlc.arg(expected_notice_schema)::text ELSE false END
  ELSE false END)::boolean AS notice_schema_matches_input
FROM documents d
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d;


-- name: ReadHTMLCeremonyParticipantPolicyV1 :one
-- ACTUAL typed document policy projection after its separate raw/body loan.
-- Used together with the actual recipient row for original private presented-
-- credential/notice predicates; never fabricate a partial generated.Document.
-- Source JSON/cache/body admission follows original notice/state/credential
-- decisions. No lawful-basis confirmation is added to these workflows.
SELECT d.id,d.org_id,d.updated_at,d.name,d.lawful_basis,d.article13_notice_schema,
 d.sent_at,d.article13_notice_epoch_at,d.expires_at,d.article13_notice_epoch_v61_committed
FROM documents d
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (octet_length(d.name)::numeric+octet_length(d.lawful_basis)+octet_length(d.article13_notice_schema))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;


-- name: GetHTMLChangeNotificationSenderHeaderV1 :one
-- Original notification selected stored sender UUID via GetUser, without an
-- actor role or same-org requirement. Preserve that exact actual-row domain.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.sender_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d
)
SELECT u.id AS user_id,u.org_id AS user_org_id,d.id AS document_id,d.org_id,
 (octet_length(u.name)::numeric+octet_length(u.email)+octet_length(u.role)+COALESCE(octet_length(u.zitadel_sub),0))::bigint AS raw_text_bytes
FROM users u JOIN parent d ON d.sender_id=u.id FOR SHARE OF u;

-- name: ReadHTMLChangeNotificationSenderV1 :one
-- Actual full User after its own raw-derived loan, retaining the exact parent
-- and sender SHARE. expected_user_org_id is the HEADER'S actual row identity,
-- not a new equality to document org or a permission/role requirement.
SELECT u.* FROM users u JOIN documents d ON d.sender_id=u.id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND u.id=sqlc.arg(expected_user_id)::uuid AND u.org_id=sqlc.arg(expected_user_org_id)::uuid
 AND (octet_length(u.name)::numeric+octet_length(u.email)+octet_length(u.role)+COALESCE(octet_length(u.zitadel_sub),0))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;


-- name: GetHTMLCeremonyImplementationV1 :one
-- Minimal original legacy transaction classification before its full document
-- read. Genuine HTML refuses without fallback when native runtime is absent;
-- actual non-HTML keeps its unchanged original full-body and policy path.
-- A scalar nullable-column presence test expands no source/cache/body data.
SELECT (d.html_source_json IS NOT NULL)::boolean AS has_html_source
FROM documents d
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL FOR UPDATE OF d;


-- name: GetHTMLCeremonyParticipantRecipientHeaderV1 :one
-- Original mutation locks actual recipient UUID before its private token/role/
-- original-deadline check. A rotated token must not be hidden by a hash-filtered
-- read NoRows. Charge ALL six full Recipient TEXT fields and actual hash bytes;
-- no token/hash/status/text body is projected before the genuine raw loan.
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL FOR UPDATE OF d
)
SELECT r.id AS recipient_id,r.document_id,d.org_id,
 (octet_length(r.role)::numeric+octet_length(r.email)+octet_length(r.name)+octet_length(r.status)
  +COALESCE(octet_length(r.declined_reason),0)+octet_length(r.locale)+COALESCE(octet_length(r.magic_token_hash),0))::bigint AS raw_text_bytes
FROM recipients r JOIN parent d ON d.id=r.document_id
WHERE r.id=sqlc.arg(recipient_id)::uuid FOR SHARE OF r;
