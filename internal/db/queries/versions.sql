-- name: InsertDocumentVersion :one
INSERT INTO document_versions (
    document_id, org_id, version_no,
    block_tree_json, variables_json, name, source_kind,
    summary, created_by, created_via, parent_id, schema_version,
    html_source_json, html_materialization_id
) VALUES (
    $1, $2, $3,
    $4, $5, $6, $7,
    $8, $9, $10, $11, $12,
    sqlc.narg(html_source_json)::jsonb, sqlc.narg(html_materialization_id)::uuid
) RETURNING *;

-- name: GetDocumentVersion :one
SELECT * FROM document_versions WHERE id = $1;

-- name: GetDocumentVersionByNo :one
SELECT * FROM document_versions
WHERE document_id = $1 AND version_no = $2;

-- name: GetLatestDocumentVersionNo :one
SELECT COALESCE(MAX(version_no), 0)::int AS max_version
FROM document_versions
WHERE document_id = $1;

-- name: ListDocumentVersions :many
-- Inline master assets are available only through an explicit version read.
-- A bounded history list must not multiply multi-megabyte sources by 200 rows.
SELECT id, document_id, org_id, version_no, block_tree_json, variables_json,
       name, source_kind, summary, created_by, created_via, created_at,
       parent_id, schema_version, NULL::jsonb AS html_source_json, html_materialization_id
FROM document_versions
WHERE document_id = $1
ORDER BY version_no DESC
LIMIT $2;

-- name: GetLatestDocumentVersion :one
SELECT * FROM document_versions
WHERE document_id = $1
ORDER BY version_no DESC
LIMIT 1;

-- name: CountDocumentVersions :one
SELECT COUNT(*)::int FROM document_versions WHERE document_id = $1;
