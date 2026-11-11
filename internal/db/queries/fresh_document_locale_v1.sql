-- Only a genuine fresh creation owner invokes this before its original audit
-- and commit. Existing documents and recipient language choices are untouched.
-- name: SetFreshDocumentLocaleV1 :one
UPDATE documents
SET default_locale = sqlc.arg(locale)::text, updated_at = clock_timestamp()
WHERE id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  AND updated_at = sqlc.arg(expected_updated_at)::timestamptz
  AND status = 'draft' AND deleted_at IS NULL AND sent_at IS NULL
  AND default_locale = 'en'
RETURNING *;
