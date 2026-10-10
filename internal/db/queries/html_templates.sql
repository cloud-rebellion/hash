-- name: InsertHTMLTemplateRevision :one
-- Caller holds the current template FOR UPDATE through insertion and audit.
-- Persist only the exact current row snapshot; supplied canonical digest is
-- computed and checked by the versioned HTML-master parser.
INSERT INTO html_template_revisions (
    template_id, version, org_id, html_master_json, variables_json,
    content_sha256, created_by
)
SELECT t.id, t.version, t.org_id, t.html_master_json, t.variables_json,
       sqlc.arg(content_sha256)::bytea, sqlc.arg(created_by)::uuid
FROM templates t
WHERE t.id = sqlc.arg(template_id)::uuid AND t.org_id = sqlc.arg(org_id)::uuid
  AND t.source_kind = 'html' AND t.archived_at IS NULL
  AND t.version = sqlc.arg(expected_version)::integer
  AND t.html_content_sha256 = sqlc.arg(content_sha256)::bytea
  AND t.html_master_json = sqlc.arg(html_master_json)::jsonb
  AND t.variables_json = sqlc.arg(variables_json)::jsonb
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = sqlc.arg(created_by)::uuid
      AND u.org_id = t.org_id AND u.role IN ('owner', 'sender'))
RETURNING *;

-- name: GetHTMLTemplateRevision :one
-- Old revisions remain readable while their tenant template is active.
SELECT r.* FROM html_template_revisions r
JOIN templates t ON t.id = r.template_id AND t.org_id = r.org_id
WHERE r.template_id = sqlc.arg(template_id)::uuid AND r.org_id = sqlc.arg(org_id)::uuid
  AND r.version = sqlc.arg(version)::integer
  AND t.source_kind = 'html' AND t.archived_at IS NULL;

-- name: GetHTMLTemplateRevisionForShare :one
-- Instantiation retains the exact revision lock until its document commits.
SELECT r.* FROM html_template_revisions r
JOIN templates t ON t.id = r.template_id AND t.org_id = r.org_id
WHERE r.template_id = sqlc.arg(template_id)::uuid AND r.org_id = sqlc.arg(org_id)::uuid
  AND r.version = sqlc.arg(version)::integer
  AND t.source_kind = 'html' AND t.archived_at IS NULL
FOR SHARE OF r;

-- name: ApproveHTMLTemplateRevision :one
-- Caller retains the current template and live owner guard through audit and
-- commit. Only the current exact digest can receive its first approval.
UPDATE html_template_revisions r
SET approved_by = sqlc.arg(approved_by)::uuid, approved_at = clock_timestamp()
FROM templates t
WHERE r.template_id = sqlc.arg(template_id)::uuid AND r.org_id = sqlc.arg(org_id)::uuid
  AND r.version = sqlc.arg(expected_version)::integer
  AND r.content_sha256 = sqlc.arg(expected_content_sha256)::bytea
  AND r.approved_by IS NULL AND r.approved_at IS NULL
  AND t.id = r.template_id AND t.org_id = r.org_id
  AND t.source_kind = 'html' AND t.archived_at IS NULL AND t.version = r.version
  AND t.html_content_sha256 = r.content_sha256
  AND t.html_master_json = r.html_master_json AND t.variables_json = r.variables_json
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = sqlc.arg(approved_by)::uuid
      AND u.org_id = r.org_id AND u.role = 'owner')
RETURNING r.*;

-- name: ListApprovedHTMLTemplateRevisions :many
SELECT r.* FROM html_template_revisions r
JOIN templates t ON t.id = r.template_id AND t.org_id = r.org_id
WHERE r.template_id = sqlc.arg(template_id)::uuid AND r.org_id = sqlc.arg(org_id)::uuid
  AND t.source_kind = 'html' AND t.archived_at IS NULL
  AND r.approved_by IS NOT NULL AND r.approved_at IS NOT NULL
ORDER BY r.version DESC
LIMIT sqlc.arg(result_limit)::integer;
