-- Fixed native Send source configuration. The owning session has already
-- locked its scoped document; each API repeats that scope before locking the
-- actual source row. No credential or JSON bodies are expanded in a header.

-- name: GetHTMLSendOrgSourceReadHeaderV1 :one
WITH document_scope AS MATERIALIZED (
    SELECT d0.id, d0.org_id FROM documents d0
    WHERE d0.id = sqlc.arg(document_id) AND d0.org_id = sqlc.arg(org_id)
      AND CASE WHEN octet_length(d0.source_kind) = 3 THEN d0.source_kind = 'pdf' ELSE false END
      AND d0.html_source_json IS NOT NULL AND d0.deleted_at IS NULL
      AND NOT d0.is_envelope AND d0.parent_envelope_id IS NULL
    FOR UPDATE OF d0
), source_lock AS MATERIALIZED (
    SELECT o.id, o.created_at, o.updated_at,
           (octet_length(o.name)::numeric + octet_length(o.plan)::numeric
            + octet_length(o.change_approval_mode)::numeric)::bigint AS raw_text_bytes
    FROM orgs o JOIN document_scope d ON d.org_id = o.id
    FOR SHARE OF o
)
SELECT s.id AS org_id, s.created_at, s.updated_at, s.raw_text_bytes FROM source_lock s;

-- name: ReadHTMLSendOrgSourceV1 :one
SELECT o.* FROM orgs o
WHERE o.id = sqlc.arg(org_id)
  AND o.created_at = sqlc.arg(expected_created_at)
  AND o.updated_at = sqlc.arg(expected_updated_at)
  AND (octet_length(o.name)::numeric + octet_length(o.plan)::numeric
       + octet_length(o.change_approval_mode)::numeric)::bigint = sqlc.arg(expected_raw_text_bytes)::bigint
  AND EXISTS (SELECT 1 FROM documents d
              WHERE d.id = sqlc.arg(document_id) AND d.org_id = o.id
                AND CASE WHEN octet_length(d.source_kind) = 3 THEN d.source_kind = 'pdf' ELSE false END
                AND d.html_source_json IS NOT NULL AND d.deleted_at IS NULL
                AND NOT d.is_envelope AND d.parent_envelope_id IS NULL);

-- name: GetHTMLSendOrgBrandingSourceReadHeaderV1 :one
WITH document_scope AS MATERIALIZED (
    SELECT d0.id, d0.org_id FROM documents d0
    WHERE d0.id = sqlc.arg(document_id) AND d0.org_id = sqlc.arg(org_id)
      AND CASE WHEN octet_length(d0.source_kind) = 3 THEN d0.source_kind = 'pdf' ELSE false END
      AND d0.html_source_json IS NOT NULL AND d0.deleted_at IS NULL
      AND NOT d0.is_envelope AND d0.parent_envelope_id IS NULL
    FOR UPDATE OF d0
), source_lock AS MATERIALIZED (
    SELECT b.org_id, b.created_at, b.updated_at, b.schema_version,
           (octet_length(b.primary_hex)::numeric + octet_length(b.accent_hex)::numeric
            + octet_length(b.surface_hex)::numeric + octet_length(b.text_hex)::numeric
            + octet_length(b.muted_hex)::numeric + octet_length(b.logo_url)::numeric
            + octet_length(b.logo_alt)::numeric + octet_length(b.font_heading)::numeric
            + octet_length(b.font_body)::numeric + octet_length(b.signature_color)::numeric)::bigint AS raw_text_bytes
    FROM org_branding b JOIN document_scope d ON d.org_id = b.org_id
    FOR SHARE OF b
)
SELECT s.org_id, s.created_at, s.updated_at, s.schema_version, s.raw_text_bytes FROM source_lock s;

-- name: ReadHTMLSendOrgBrandingSourceV1 :one
SELECT b.* FROM org_branding b
WHERE b.org_id = sqlc.arg(org_id)
  AND b.created_at = sqlc.arg(expected_created_at)
  AND b.updated_at = sqlc.arg(expected_updated_at)
  AND b.schema_version = sqlc.arg(expected_schema_version)
  AND (octet_length(b.primary_hex)::numeric + octet_length(b.accent_hex)::numeric
       + octet_length(b.surface_hex)::numeric + octet_length(b.text_hex)::numeric
       + octet_length(b.muted_hex)::numeric + octet_length(b.logo_url)::numeric
       + octet_length(b.logo_alt)::numeric + octet_length(b.font_heading)::numeric
       + octet_length(b.font_body)::numeric + octet_length(b.signature_color)::numeric)::bigint = sqlc.arg(expected_raw_text_bytes)::bigint
  AND EXISTS (SELECT 1 FROM documents d
              WHERE d.id = sqlc.arg(document_id) AND d.org_id = b.org_id
                AND CASE WHEN octet_length(d.source_kind) = 3 THEN d.source_kind = 'pdf' ELSE false END
                AND d.html_source_json IS NOT NULL AND d.deleted_at IS NULL
                AND NOT d.is_envelope AND d.parent_envelope_id IS NULL);

-- name: GetHTMLSendCRMReviewReadHeaderV1 :one
WITH document_scope AS MATERIALIZED (
    SELECT d0.id, d0.org_id FROM documents d0
    WHERE d0.id = sqlc.arg(document_id) AND d0.org_id = sqlc.arg(org_id)
      AND d0.deleted_at IS NULL
    FOR UPDATE OF d0
), source_lock AS MATERIALIZED (
    SELECT r.document_id, r.created_at, r.updated_at,
           (octet_length(r.binding_digest)::numeric + octet_length(r.content_commitment)::numeric
            + octet_length(r.origin)::numeric + octet_length(r.crm_team_id)::numeric
            + octet_length(r.crm_user_id)::numeric)::bigint AS raw_text_bytes
    FROM document_crm_mapping_reviews r JOIN document_scope d ON d.id = r.document_id
    FOR SHARE OF r NOWAIT
)
SELECT s.document_id, s.created_at, s.updated_at, s.raw_text_bytes FROM source_lock s;

-- name: ReadHTMLSendCRMReviewV1 :one
SELECT r.* FROM document_crm_mapping_reviews r
JOIN documents d ON d.id = r.document_id
WHERE d.id = sqlc.arg(document_id) AND d.org_id = sqlc.arg(org_id)
  AND d.deleted_at IS NULL
  AND r.created_at = sqlc.arg(expected_created_at)
  AND r.updated_at = sqlc.arg(expected_updated_at)
  AND (octet_length(r.binding_digest)::numeric + octet_length(r.content_commitment)::numeric
       + octet_length(r.origin)::numeric + octet_length(r.crm_team_id)::numeric
       + octet_length(r.crm_user_id)::numeric)::bigint = sqlc.arg(expected_raw_text_bytes)::bigint;
