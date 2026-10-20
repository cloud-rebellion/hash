-- Native response admission only. The original response owns the root UPDATE
-- and all envelope-member UPDATE locks before its provisional audit append.
-- The scalar clock includes every retained family producer; no body, caller
-- timestamp or later read of an unlocked family becomes cutoff authority.
-- name: GetResponseReportClockV1 :one
WITH root AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.deleted_at IS NULL AND d.parent_envelope_id IS NULL
 AND d.status IN ('sent','in_progress','finalizing') FOR UPDATE OF d
), family AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d JOIN root r ON d.org_id=r.org_id
 AND (d.id=r.id OR d.parent_envelope_id=r.id) WHERE d.deleted_at IS NULL
)
SELECT r.id AS document_id,r.org_id,r.updated_at AS source_updated_at,
 GREATEST(clock_timestamp(),r.updated_at,
 COALESCE((SELECT max(e.created_at) FROM events e JOIN family f ON f.id=e.document_id AND f.org_id=e.org_id),'-infinity'::timestamptz),
 COALESCE((SELECT max(c.created_at) FROM document_comments c JOIN family f ON f.id=c.document_id),'-infinity'::timestamptz),
 COALESCE((SELECT max(v.created_at) FROM document_versions v JOIN family f ON f.id=v.document_id AND f.org_id=v.org_id),'-infinity'::timestamptz),
 COALESCE((SELECT max(p.updated_at) FROM document_proposals p JOIN family f ON f.id=p.document_id AND f.org_id=p.org_id),'-infinity'::timestamptz))::timestamptz AS cutoff
FROM root r;
