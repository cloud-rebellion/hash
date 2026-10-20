-- Scalar-only frozen theme source for the historical finalizer. Never reads
-- mutable organization branding/defaults or expands an unpriced theme body.
-- name: GetHistoricalFinalizationFrozenBrandingReadHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT d.id,d.org_id,d.updated_at FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
  AND d.deleted_at IS NULL AND d.status='finalizing' FOR UPDATE OF d
), frozen AS MATERIALIZED (
 SELECT b.document_id,b.updated_at,(COALESCE(octet_length(b.primary_hex),0)::numeric+COALESCE(octet_length(b.accent_hex),0)::numeric+COALESCE(octet_length(b.surface_hex),0)::numeric+COALESCE(octet_length(b.text_hex),0)::numeric+COALESCE(octet_length(b.muted_hex),0)::numeric+COALESCE(octet_length(b.logo_url),0)::numeric+COALESCE(octet_length(b.logo_alt),0)::numeric+COALESCE(octet_length(b.font_heading),0)::numeric+COALESCE(octet_length(b.font_body),0)::numeric+COALESCE(octet_length(b.signature_color),0)::numeric)::bigint AS raw_text_bytes
 FROM document_branding_override b JOIN parent d ON d.id=b.document_id FOR SHARE OF b
)
SELECT d.id AS document_id,d.org_id,d.updated_at AS source_updated_at,
 (b.document_id IS NOT NULL)::boolean AS has_frozen_branding,
 b.updated_at AS branding_updated_at,COALESCE(b.raw_text_bytes,0)::bigint AS raw_text_bytes
FROM parent d LEFT JOIN frozen b ON b.document_id=d.id;
