-- Headers are fixed scalars only. The actual parent is already locked by the
-- native owner; these exact selected comment rows stay locked until commit.
-- Lengths come from the stored historical text, never today's POST limit.
-- name: ListLatestCommentWindowHeadersV1 :many
SELECT c.id, c.document_id, c.created_at,
       octet_length(c.author_name)::bigint AS author_bytes,
       octet_length(c.author_side)::bigint AS side_bytes,
       octet_length(c.body)::bigint AS body_bytes
FROM document_comments c
JOIN documents d ON d.id=c.document_id
WHERE c.document_id=$1 AND d.org_id=$2 AND d.deleted_at IS NULL
ORDER BY c.created_at DESC, c.id DESC
LIMIT 51
FOR SHARE OF c;

-- name: ListOlderCommentWindowHeadersV1 :many
SELECT c.id, c.document_id, c.created_at,
       octet_length(c.author_name)::bigint AS author_bytes,
       octet_length(c.author_side)::bigint AS side_bytes,
       octet_length(c.body)::bigint AS body_bytes
FROM document_comments c
JOIN documents d ON d.id=c.document_id
WHERE c.document_id=$1 AND d.org_id=$2 AND d.deleted_at IS NULL
  AND (c.created_at,c.id)<(sqlc.arg(boundary_at)::timestamptz,sqlc.arg(boundary_id)::uuid)
ORDER BY c.created_at DESC, c.id DESC
LIMIT 51
FOR SHARE OF c;

-- name: ListNewerCommentWindowHeadersV1 :many
SELECT c.id, c.document_id, c.created_at,
       octet_length(c.author_name)::bigint AS author_bytes,
       octet_length(c.author_side)::bigint AS side_bytes,
       octet_length(c.body)::bigint AS body_bytes
FROM document_comments c
JOIN documents d ON d.id=c.document_id
WHERE c.document_id=$1 AND d.org_id=$2 AND d.deleted_at IS NULL
  AND (c.created_at,c.id)>(sqlc.arg(boundary_at)::timestamptz,sqlc.arg(boundary_id)::uuid)
ORDER BY c.created_at ASC, c.id ASC
LIMIT 51
FOR SHARE OF c;

-- name: ReadCommentWindowRowsV1 :many
SELECT c.* FROM document_comments c
JOIN documents d ON d.id=c.document_id
WHERE c.document_id=$1 AND d.org_id=$2 AND d.deleted_at IS NULL
  AND c.id=ANY(sqlc.arg(comment_ids)::uuid[])
ORDER BY c.created_at ASC, c.id ASC
FOR SHARE OF c;

-- name: GetCommentWindowEdgesV1 :one
SELECT
 EXISTS(SELECT 1 FROM document_comments c JOIN documents d ON d.id=c.document_id
        WHERE c.document_id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id) AND d.deleted_at IS NULL
          AND (c.created_at,c.id)<(sqlc.arg(oldest_at)::timestamptz,sqlc.arg(oldest_id)::uuid)) AS has_older,
 EXISTS(SELECT 1 FROM document_comments c JOIN documents d ON d.id=c.document_id
        WHERE c.document_id=sqlc.arg(document_id) AND d.org_id=sqlc.arg(org_id) AND d.deleted_at IS NULL
          AND (c.created_at,c.id)>(sqlc.arg(newest_at)::timestamptz,sqlc.arg(newest_id)::uuid)) AS has_newer;
