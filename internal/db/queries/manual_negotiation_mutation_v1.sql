-- Scalar discovery is not authorization. The genuine native writer locks the
-- actual physical root before its actual target/actor reader.
-- name: GetManualNegotiationRootV1 :one
SELECT r.id FROM documents d JOIN documents r
 ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL;

-- name: LockManualNegotiationRootV1 :one
SELECT r.id AS root_document_id,r.is_envelope,(r.parent_envelope_id IS NOT NULL)::boolean AS root_has_parent FROM documents r
WHERE r.id=sqlc.arg(root_document_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
 AND r.deleted_at IS NULL
FOR UPDATE OF r;

-- Fresh statement after the possible root wait; no automatic scope retry.
-- name: ManualNegotiationRootMatchesV1 :one
SELECT EXISTS(SELECT 1 FROM documents d JOIN documents r
 ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND r.id=sqlc.arg(root_document_id)::uuid
 AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL
 AND (d.id=r.id OR r.is_envelope));

-- Both document locks precede these fixed scalar facts. Status refusals stay
-- after the original member/credential and organization privacy-fence stages.
-- name: GetManualNegotiationPolicyV1 :one
SELECT r.id AS root_document_id,d.id AS document_id,
 CASE WHEN octet_length(r.status)<=17 THEN r.status='draft' ELSE false END AS root_draft,
 CASE WHEN octet_length(d.status)<=17 THEN d.status='draft' ELSE false END AS document_draft,
 CASE WHEN octet_length(r.status)<=17 THEN r.status IN ('draft','sent','in_progress','changes_requested') ELSE false END AS root_allowed,
 CASE WHEN octet_length(d.status)<=17 THEN d.status IN ('draft','sent','in_progress','changes_requested') ELSE false END AS document_allowed
FROM documents d JOIN documents r ON r.id=COALESCE(d.parent_envelope_id,d.id) AND r.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND r.id=sqlc.arg(root_document_id)::uuid
 AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL;

-- Compare only after the size guard, without expanding a larger unrelated
-- parent block value. The original same-document parent lock is retained.
-- name: LockManualProposalParentV1 :one
SELECT CASE WHEN octet_length(p.block_id)=octet_length(sqlc.arg(block_id)::text)
 THEN p.block_id=sqlc.arg(block_id)::text ELSE false END AS block_matches
FROM document_proposals p WHERE p.id=sqlc.arg(proposal_id)::uuid
 AND p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid FOR UPDATE OF p;

-- Actual old text and JSONB wire sizing precedes full body/status RETURNING.
-- name: GetManualProposalHeaderV1 :one
SELECT p.id,p.document_id,p.org_id,p.created_at,p.updated_at,
 (octet_length(p.block_id)::numeric+octet_length(p.proposal_kind)::numeric
 +octet_length(p.proposed_text)::numeric+octet_length(p.rationale)::numeric
 +octet_length(p.status)::numeric)::bigint AS raw_text_bytes,
 COALESCE(m.diff_wire_bytes,-1::bigint)::bigint AS diff_wire_bytes,
 COALESCE(m.measurement_server_version_num,0)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM document_proposals p LEFT JOIN manual_proposal_wire_sizes_v1 m
 ON m.proposal_id=p.id AND m.document_id=p.document_id AND m.org_id=p.org_id
 AND m.proposal_created_at=p.created_at AND m.proposal_updated_at=p.updated_at
WHERE p.id=sqlc.arg(proposal_id)::uuid
 AND p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid FOR UPDATE OF p;

-- name: ReadManualProposalSourceV1 :one
SELECT p.* FROM document_proposals p
WHERE p.id=sqlc.arg(proposal_id)::uuid AND p.document_id=sqlc.arg(document_id)::uuid
 AND p.org_id=sqlc.arg(org_id)::uuid
 AND p.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND p.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (octet_length(p.block_id)::numeric+octet_length(p.proposal_kind)::numeric
 +octet_length(p.proposed_text)::numeric+octet_length(p.rationale)::numeric
 +octet_length(p.status)::numeric)::bigint=sqlc.arg(expected_raw_text_bytes)::bigint
 AND octet_length(p.diff_json::text)::bigint=sqlc.arg(expected_diff_wire_bytes)::bigint;

-- This is reached only after native birth/status owns its actual old/new body.
-- The trigger derives scope/stamps/wire bytes from the locked actual proposal.
-- name: MeasureManualProposalWireV1 :one
INSERT INTO manual_proposal_wire_sizes_v1(proposal_id,document_id,org_id,proposal_created_at,proposal_updated_at,diff_wire_bytes,measurement_server_version_num,measured_at)
SELECT p.id,p.document_id,p.org_id,p.created_at,p.updated_at,0,current_setting('server_version_num')::integer,clock_timestamp()
FROM document_proposals p
WHERE p.id=sqlc.arg(proposal_id)::uuid AND p.document_id=sqlc.arg(document_id)::uuid
 AND p.org_id=sqlc.arg(org_id)::uuid
 AND p.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND p.updated_at=sqlc.arg(expected_updated_at)::timestamptz
RETURNING *;
