-- Additive fixed native LEGACY Send source reads. Original HTML-only APIs
-- remain unchanged. These scalar UUID/format/topology/clock inputs are derived
-- privately from the current original preparation Work and registered member
-- owner, never exposed as caller authority. Root first, then already-owned
-- member, then actual source row. No body, JSON expansion, repair or measurement
-- is performed by a header. Full source text follows its actual sized loan.

-- name: GetLegacySendOrgSourceReadHeaderV1 :one
WITH root_scope AS MATERIALIZED (
 SELECT r.id,r.org_id FROM documents r
 WHERE r.id=sqlc.arg(root_document_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
  AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL
  AND r.updated_at=sqlc.arg(expected_root_updated_at)::timestamptz
  AND r.html_source_json IS NULL
  AND r.is_envelope=sqlc.arg(expected_root_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_root_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(r.source_kind)=3 THEN r.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(r.source_kind)=6 THEN r.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(r.status)=5 THEN r.status='draft' ELSE false END
  AND (r.id=sqlc.arg(document_id)::uuid OR r.is_envelope)
 FOR UPDATE OF r
), document_scope AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d JOIN root_scope r ON r.org_id=d.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.deleted_at IS NULL
  AND d.updated_at=sqlc.arg(expected_document_updated_at)::timestamptz
  AND d.html_source_json IS NULL
  AND d.is_envelope=sqlc.arg(expected_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(d.source_kind)=3 THEN d.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(d.source_kind)=6 THEN d.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(d.status)=5 THEN d.status='draft' ELSE false END
  AND CASE WHEN d.id=r.id THEN d.parent_envelope_id IS NULL
           ELSE d.parent_envelope_id=r.id AND NOT d.is_envelope END
 -- Real preparation already owns the root and its ordered members. Never wait
 -- for a member while trying to recover a root lock in the reverse direction.
 FOR UPDATE OF d NOWAIT
), source_lock AS MATERIALIZED (
 SELECT o.id AS org_id,o.created_at,o.updated_at,
  (octet_length(o.name)::numeric+octet_length(o.plan)::numeric
  +octet_length(o.change_approval_mode)::numeric)::bigint AS raw_text_bytes
 FROM orgs o JOIN document_scope d ON d.org_id=o.id FOR SHARE OF o
)
SELECT s.org_id,s.created_at,s.updated_at,s.raw_text_bytes FROM source_lock s;

-- name: ReadLegacySendOrgSourceV1 :one
WITH root_scope AS MATERIALIZED (
 SELECT r.id,r.org_id FROM documents r
 WHERE r.id=sqlc.arg(root_document_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
  AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL
  AND r.updated_at=sqlc.arg(expected_root_updated_at)::timestamptz
  AND r.html_source_json IS NULL
  AND r.is_envelope=sqlc.arg(expected_root_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_root_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(r.source_kind)=3 THEN r.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(r.source_kind)=6 THEN r.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(r.status)=5 THEN r.status='draft' ELSE false END
  AND (r.id=sqlc.arg(document_id)::uuid OR r.is_envelope)
 FOR UPDATE OF r
), document_scope AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d JOIN root_scope r ON r.org_id=d.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.deleted_at IS NULL
  AND d.updated_at=sqlc.arg(expected_document_updated_at)::timestamptz
  AND d.html_source_json IS NULL
  AND d.is_envelope=sqlc.arg(expected_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(d.source_kind)=3 THEN d.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(d.source_kind)=6 THEN d.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(d.status)=5 THEN d.status='draft' ELSE false END
  AND CASE WHEN d.id=r.id THEN d.parent_envelope_id IS NULL
           ELSE d.parent_envelope_id=r.id AND NOT d.is_envelope END
 -- Real preparation already owns the root and its ordered members. Never wait
 -- for a member while trying to recover a root lock in the reverse direction.
 FOR UPDATE OF d NOWAIT
)
SELECT o.* FROM orgs o JOIN document_scope d ON d.org_id=o.id
WHERE o.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND o.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (octet_length(o.name)::numeric+octet_length(o.plan)::numeric
  +octet_length(o.change_approval_mode)::numeric)::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: GetLegacySendOrgBrandingSourceReadHeaderV1 :one
WITH root_scope AS MATERIALIZED (
 SELECT r.id,r.org_id FROM documents r
 WHERE r.id=sqlc.arg(root_document_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
  AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL
  AND r.updated_at=sqlc.arg(expected_root_updated_at)::timestamptz
  AND r.html_source_json IS NULL
  AND r.is_envelope=sqlc.arg(expected_root_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_root_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(r.source_kind)=3 THEN r.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(r.source_kind)=6 THEN r.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(r.status)=5 THEN r.status='draft' ELSE false END
  AND (r.id=sqlc.arg(document_id)::uuid OR r.is_envelope)
 FOR UPDATE OF r
), document_scope AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d JOIN root_scope r ON r.org_id=d.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.deleted_at IS NULL
  AND d.updated_at=sqlc.arg(expected_document_updated_at)::timestamptz
  AND d.html_source_json IS NULL
  AND d.is_envelope=sqlc.arg(expected_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(d.source_kind)=3 THEN d.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(d.source_kind)=6 THEN d.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(d.status)=5 THEN d.status='draft' ELSE false END
  AND CASE WHEN d.id=r.id THEN d.parent_envelope_id IS NULL
           ELSE d.parent_envelope_id=r.id AND NOT d.is_envelope END
 -- Real preparation already owns the root and its ordered members. Never wait
 -- for a member while trying to recover a root lock in the reverse direction.
 FOR UPDATE OF d NOWAIT
), source_lock AS MATERIALIZED (
 SELECT b.org_id,b.created_at,b.updated_at,b.schema_version,
  (octet_length(b.primary_hex)::numeric+octet_length(b.accent_hex)::numeric
  +octet_length(b.surface_hex)::numeric+octet_length(b.text_hex)::numeric
  +octet_length(b.muted_hex)::numeric+octet_length(b.logo_url)::numeric
  +octet_length(b.logo_alt)::numeric+octet_length(b.font_heading)::numeric
  +octet_length(b.font_body)::numeric+octet_length(b.signature_color)::numeric)::bigint AS raw_text_bytes
 FROM org_branding b JOIN document_scope d ON d.org_id=b.org_id FOR SHARE OF b
)
SELECT s.org_id,s.created_at,s.updated_at,s.schema_version,s.raw_text_bytes FROM source_lock s;

-- name: ReadLegacySendOrgBrandingSourceV1 :one
WITH root_scope AS MATERIALIZED (
 SELECT r.id,r.org_id FROM documents r
 WHERE r.id=sqlc.arg(root_document_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
  AND r.deleted_at IS NULL AND r.parent_envelope_id IS NULL
  AND r.updated_at=sqlc.arg(expected_root_updated_at)::timestamptz
  AND r.html_source_json IS NULL
  AND r.is_envelope=sqlc.arg(expected_root_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_root_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(r.source_kind)=3 THEN r.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(r.source_kind)=6 THEN r.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(r.status)=5 THEN r.status='draft' ELSE false END
  AND (r.id=sqlc.arg(document_id)::uuid OR r.is_envelope)
 FOR UPDATE OF r
), document_scope AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d JOIN root_scope r ON r.org_id=d.org_id
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.deleted_at IS NULL
  AND d.updated_at=sqlc.arg(expected_document_updated_at)::timestamptz
  AND d.html_source_json IS NULL
  AND d.is_envelope=sqlc.arg(expected_is_envelope)::boolean
  AND CASE WHEN sqlc.arg(expected_is_pdf_source)::boolean
       THEN CASE WHEN octet_length(d.source_kind)=3 THEN d.source_kind='pdf' ELSE false END
       ELSE CASE WHEN octet_length(d.source_kind)=6 THEN d.source_kind='blocks' ELSE false END END
  AND CASE WHEN octet_length(d.status)=5 THEN d.status='draft' ELSE false END
  AND CASE WHEN d.id=r.id THEN d.parent_envelope_id IS NULL
           ELSE d.parent_envelope_id=r.id AND NOT d.is_envelope END
 -- Real preparation already owns the root and its ordered members. Never wait
 -- for a member while trying to recover a root lock in the reverse direction.
 FOR UPDATE OF d NOWAIT
)
SELECT b.* FROM org_branding b JOIN document_scope d ON d.org_id=b.org_id
WHERE b.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND b.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND b.schema_version=sqlc.arg(expected_schema_version)::integer
 AND (octet_length(b.primary_hex)::numeric+octet_length(b.accent_hex)::numeric
  +octet_length(b.surface_hex)::numeric+octet_length(b.text_hex)::numeric
  +octet_length(b.muted_hex)::numeric+octet_length(b.logo_url)::numeric
  +octet_length(b.logo_alt)::numeric+octet_length(b.font_heading)::numeric
  +octet_length(b.font_body)::numeric+octet_length(b.signature_color)::numeric)::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;
