-- Complete bounded retained participant history. The actual native owner has
-- already locked the root. No LIMIT is a successful truncated attestation.
-- Text octet lengths are scalar producer measurements; no JSON is expanded.
-- name: GetParticipantReportHeaderV1 :one
WITH family AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d WHERE d.org_id=sqlc.arg(org_id)::uuid
 AND (d.id=sqlc.arg(document_id)::uuid OR d.parent_envelope_id=sqlc.arg(document_id)::uuid)
 AND d.deleted_at IS NULL
), bindings AS MATERIALIZED (
 SELECT a.attempt_id,a.package_id,a.capture_revision FROM document_package_send_attempts_v1 a
 JOIN document_package_send_completions_v1 c ON c.attempt_id=a.attempt_id AND c.outcome='sent'
 JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND a.terminal_outcome='completed' AND a.article13_notice_epoch_at=d.article13_notice_epoch_at
 AND a.article13_notice_epoch_at=d.sent_at
), measures AS (
 SELECT 'event' AS kind,octet_length(e.kind)::bigint+COALESCE(octet_length(e.ua),0)+COALESCE(octet_length(e.prev_hash),0)+COALESCE(octet_length(e.row_hash),0)+COALESCE(octet_length(e.payload_hashed),0)+COALESCE((SELECT z.payload_wire_bytes FROM html_snapshot_event_payload_sizes_v1 z WHERE z.event_id=e.id AND z.document_id=e.document_id AND z.org_id=e.org_id),0) AS raw FROM events e JOIN family f ON f.id=e.document_id AND f.org_id=e.org_id WHERE e.created_at<=sqlc.arg(cutoff)::timestamptz
 UNION ALL SELECT 'comment',octet_length(c.author_name)::bigint+octet_length(c.author_side)+octet_length(c.body) AS raw FROM document_comments c JOIN family f ON f.id=c.document_id WHERE c.created_at<=sqlc.arg(cutoff)::timestamptz
 UNION ALL SELECT 'revision',octet_length(v.name)::bigint+octet_length(v.source_kind) FROM document_versions v JOIN family f ON f.id=v.document_id AND f.org_id=v.org_id WHERE v.created_at<=sqlc.arg(cutoff)::timestamptz
 UNION ALL SELECT 'proposal',octet_length(p.proposal_kind)::bigint+octet_length(p.block_id)+octet_length(p.proposed_text)+octet_length(p.rationale)+octet_length(p.status) FROM document_proposals p JOIN family f ON f.id=p.document_id AND f.org_id=p.org_id WHERE p.created_at<=sqlc.arg(cutoff)::timestamptz AND p.updated_at<=sqlc.arg(cutoff)::timestamptz
 UNION ALL SELECT 'member',octet_length(m.title)::bigint+octet_length(m.category)+octet_length(m.pdf_version_id)+octet_length(m.pdf_sha256) FROM document_package_capture_members_v1 m JOIN bindings b ON b.package_id=m.package_id AND b.capture_revision=m.revision
 UNION ALL SELECT 'response',octet_length(r.manifest_sha256)::bigint+octet_length(r.legal_commitment_sha256)+octet_length(r.response_kind)+octet_length(r.response_event_row_sha256)+octet_length(r.incorporation_version)+octet_length(r.incorporation_sha256) FROM document_package_responses_v1 r JOIN bindings b ON b.attempt_id=r.attempt_id
)
SELECT count(*)::bigint AS row_count,COALESCE(sum(raw),0)::bigint AS raw_bytes,
 (SELECT count(*)::bigint FROM family) AS scope_count,
 COALESCE((SELECT d.participant_report_schema FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL),'')::text AS report_schema,
 (SELECT count(*)::bigint FROM bindings) AS binding_count,
 (SELECT count(*)::bigint FROM document_proposals p JOIN family f ON f.id=p.document_id AND f.org_id=p.org_id WHERE p.created_at<=sqlc.arg(cutoff)::timestamptz AND p.updated_at>sqlc.arg(cutoff)::timestamptz) AS future_mutation_count,
 (SELECT count(*)::bigint FROM events e JOIN family f ON f.id=e.document_id AND f.org_id=e.org_id WHERE e.created_at<=sqlc.arg(cutoff)::timestamptz AND NOT EXISTS(SELECT 1 FROM html_snapshot_event_payload_sizes_v1 z WHERE z.event_id=e.id AND z.document_id=e.document_id AND z.org_id=e.org_id AND z.measurement_server_version_num=current_setting('server_version_num')::integer)) AS unmeasured_event_count FROM measures;

-- name: ListParticipantReportEventRowsV1 :many
SELECT e.* FROM events e JOIN documents d ON d.id=e.document_id AND d.org_id=e.org_id
WHERE d.org_id=sqlc.arg(org_id)::uuid AND (d.id=sqlc.arg(document_id)::uuid OR d.parent_envelope_id=sqlc.arg(document_id)::uuid)
AND d.deleted_at IS NULL AND e.created_at<=sqlc.arg(cutoff)::timestamptz ORDER BY e.created_at,e.id;

-- name: ListParticipantReportCommentsV1 :many
SELECT c.* FROM document_comments c JOIN documents d ON d.id=c.document_id
WHERE d.org_id=sqlc.arg(org_id)::uuid AND (d.id=sqlc.arg(document_id)::uuid OR d.parent_envelope_id=sqlc.arg(document_id)::uuid)
AND d.deleted_at IS NULL AND c.created_at<=sqlc.arg(cutoff)::timestamptz ORDER BY c.created_at,c.id;

-- name: ListParticipantReportRevisionsV1 :many
SELECT v.id,v.document_id,v.version_no,v.name,v.source_kind,v.created_at FROM document_versions v JOIN documents d ON d.id=v.document_id AND d.org_id=v.org_id
WHERE d.org_id=sqlc.arg(org_id)::uuid AND (d.id=sqlc.arg(document_id)::uuid OR d.parent_envelope_id=sqlc.arg(document_id)::uuid)
AND d.deleted_at IS NULL AND v.created_at<=sqlc.arg(cutoff)::timestamptz ORDER BY v.created_at,v.id;

-- name: ListParticipantReportProposalsV1 :many
SELECT p.id,p.document_id,p.proposal_kind,p.block_id,p.proposed_text,p.rationale,p.status,p.created_at,p.updated_at FROM document_proposals p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id
WHERE d.org_id=sqlc.arg(org_id)::uuid AND (d.id=sqlc.arg(document_id)::uuid OR d.parent_envelope_id=sqlc.arg(document_id)::uuid)
AND d.deleted_at IS NULL AND p.created_at<=sqlc.arg(cutoff)::timestamptz AND p.updated_at<=sqlc.arg(cutoff)::timestamptz ORDER BY p.created_at,p.id;

-- name: ListParticipantReportMembersV1 :many
SELECT m.member_position,m.member_document_id,m.title,m.category,m.pdf_sha256,m.pdf_version_id,m.pdf_bytes,m.pdf_pages
FROM document_package_capture_members_v1 m JOIN document_package_send_attempts_v1 a ON a.package_id=m.package_id AND a.capture_revision=m.revision AND a.org_id=m.org_id
JOIN document_package_send_completions_v1 c ON c.attempt_id=a.attempt_id AND c.outcome='sent'
JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
AND a.terminal_outcome='completed' AND a.article13_notice_epoch_at=d.article13_notice_epoch_at AND a.article13_notice_epoch_at=d.sent_at
ORDER BY m.member_position;

-- name: ListParticipantReportResponsesV1 :many
SELECT r.* FROM document_package_responses_v1 r JOIN document_package_send_attempts_v1 a ON a.attempt_id=r.attempt_id AND a.org_id=r.org_id AND a.document_id=r.document_id
JOIN document_package_send_completions_v1 c ON c.attempt_id=a.attempt_id AND c.outcome='sent'
JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
AND a.terminal_outcome='completed' AND a.article13_notice_epoch_at=d.article13_notice_epoch_at AND a.article13_notice_epoch_at=d.sent_at
ORDER BY r.response_event_created_at,r.recipient_id;

-- The actual native owner has already locked the root and funded ScopeCount.
-- UUID order and SAME family predicate include children with no visible event.
-- NOWAIT refuses an inverse competing topology lock rather than blocking it.
-- name: ListParticipantReportHistoryScopeV2 :many
SELECT d.id FROM documents d
WHERE d.org_id=sqlc.arg(org_id)::uuid
 AND (d.id=sqlc.arg(document_id)::uuid OR d.parent_envelope_id=sqlc.arg(document_id)::uuid)
 AND d.deleted_at IS NULL
ORDER BY d.id FOR SHARE OF d NOWAIT;
