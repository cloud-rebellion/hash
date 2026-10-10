-- name: CreateBlocksTemplate :one
INSERT INTO templates (org_id, name, source_kind, blocks_json, variables_json, created_by)
VALUES ($1, $2, 'blocks', $3, $4, $5)
RETURNING *;

-- name: CreatePDFTemplate :one
INSERT INTO templates (
    org_id, name, source_kind, pdf_storage_key, pdf_sha256,
    pdf_storage_version_id, evidence_version_pin_required,
    page_count, fields_json, created_by
)
VALUES ($1, $2, 'pdf', $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetTemplate :one
SELECT * FROM templates WHERE id = $1 AND org_id = $2 AND archived_at IS NULL;

-- name: GetHTMLTemplate :one
SELECT * FROM templates
WHERE id = $1 AND org_id = $2 AND source_kind = 'html' AND archived_at IS NULL;

-- name: GetHTMLTemplateForShare :one
SELECT * FROM templates
WHERE id = $1 AND org_id = $2 AND source_kind = 'html' AND archived_at IS NULL
FOR SHARE;

-- name: GetHTMLTemplateForUpdate :one
SELECT * FROM templates
WHERE id = $1 AND org_id = $2 AND source_kind = 'html' AND archived_at IS NULL
FOR UPDATE;

-- name: CreateHTMLTemplate :one
INSERT INTO templates (org_id, name, source_kind, html_master_json, variables_json, created_by, html_content_sha256)
VALUES ($1, $2, 'html', $3, $4, $5, $6)
RETURNING *;

-- name: UpdateHTMLTemplate :one
-- Authoring edits create a new immutable revision in this transaction. A
-- completed old approval remains history and never approves the new version.
UPDATE templates
SET name = sqlc.arg(name)::text,
    html_master_json = sqlc.arg(html_master_json)::jsonb,
    variables_json = sqlc.arg(variables_json)::jsonb,
    html_content_sha256 = sqlc.arg(html_content_sha256)::bytea,
    version = version + 1,
    updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  AND source_kind = 'html' AND archived_at IS NULL
  AND version = sqlc.arg(expected_version)::integer
RETURNING *;

-- name: GetTemplateForShare :one
-- Automation materialization keeps this row lock until its document snapshot
-- commits. A concurrent edit therefore lands entirely before the pinned read
-- (and fails its precondition) or entirely after the copied snapshot.
SELECT * FROM templates
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL
FOR SHARE;

-- name: GetTemplateForUpdate :one
-- Mutations resolve omitted values from this locked current row and retain
-- the lock through authorization, audit and commit.
SELECT * FROM templates
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL
FOR UPDATE;

-- name: ListTemplates :many
-- Do not transfer/copy each potentially multi-MB inline-asset master merely to
-- display its metadata and canonical digest. Detail reads return the master.
-- Existing block/PDF response columns retain their previous values.
SELECT id, org_id, name, source_kind, blocks_json, variables_json,
       pdf_storage_key, pdf_sha256, page_count, fields_json, version,
       created_by, created_at, updated_at, archived_at,
       pdf_storage_version_id, evidence_version_pin_required,
       NULL::jsonb AS html_master_json, html_content_sha256
FROM templates
WHERE org_id = $1 AND archived_at IS NULL
ORDER BY updated_at DESC
LIMIT $2 OFFSET $3;

-- name: CountTemplates :one
SELECT COUNT(*) FROM templates WHERE org_id = $1 AND archived_at IS NULL;

-- name: UpdateBlocksTemplate :one
UPDATE templates
SET name = $3,
    blocks_json = $4,
    variables_json = $5,
    version = version + 1,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND source_kind = 'blocks' AND archived_at IS NULL
RETURNING *;

-- name: UpdatePDFTemplateFields :one
UPDATE templates
SET fields_json = $3,
    version = version + 1,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND source_kind = 'pdf' AND archived_at IS NULL
RETURNING *;

-- name: ArchiveTemplate :exec
UPDATE templates
SET archived_at = now(), updated_at = now()
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL;
