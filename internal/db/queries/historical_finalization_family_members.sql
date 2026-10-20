-- Original finalizing claim locks every actual child in UUID order before
-- allocating the shared completion timestamp. Return display/membership order
-- afterward, preserving immutable rendering order and the finite native slots.

-- name: ListHistoricalFinalizationFamilyMemberPinsV1 :many
-- Count-derived native row/slot credit MUST precede this query. Membership uses
-- precisely ListEnvelopeChildren's predicate/order; invalid child structure is
-- retained for the original business guard after genuine full-body reads.
-- Lock children in that same order under the already-held root lock. Every
-- following member state/header/body read remains in this actual transaction.
WITH root AS MATERIALIZED (
 SELECT d.id,d.org_id
 FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid
  AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
  AND d.deleted_at IS NULL
  AND d.is_envelope=TRUE
  AND d.parent_envelope_id IS NULL
 FOR UPDATE OF d
), members AS MATERIALIZED (
 SELECT child.id AS id,child.org_id,root.id AS parent_document_id,
  child.parent_envelope_id,child.envelope_position,child.created_at,
  child.updated_at,child.expires_at,child.sender_id,child.is_envelope,
  child.requires_signature,(child.deleted_at IS NOT NULL)::boolean AS is_deleted,
  (child.html_source_json IS NOT NULL)::boolean AS has_html_source,
  CASE WHEN octet_length(child.source_kind)=3
   THEN child.source_kind='pdf' ELSE false END AS is_pdf_source,
  CASE WHEN octet_length(child.source_kind)=6
   THEN child.source_kind='blocks' ELSE false END AS is_blocks_source,
  CASE WHEN octet_length(child.status)<=17
   THEN child.status ELSE ''::text END AS bounded_status,
  child.evidence_version_pins_required,child.sent_at,
  child.article13_notice_epoch_at,child.article13_notice_epoch_v61_committed,
  CASE WHEN octet_length(child.article13_notice_schema)=19
   THEN child.article13_notice_schema='hash-a13-2026-08-31'
   ELSE false END AS has_supported_article13_notice_schema
 FROM documents child JOIN root
  ON child.parent_envelope_id=root.id AND child.org_id=root.org_id
 ORDER BY child.id
 FOR UPDATE OF child
), total AS MATERIALIZED (
 SELECT count(*)::bigint AS member_count FROM members
)
SELECT members.*
FROM members CROSS JOIN total
WHERE total.member_count=sqlc.arg(expected_count)::bigint
ORDER BY members.envelope_position ASC NULLS LAST,members.created_at ASC;
