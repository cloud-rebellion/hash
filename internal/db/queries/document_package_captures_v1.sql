-- name: GetDocumentPackageCaptureHeadV1 :one
-- Owner locks actual root, then package, before this scalar read and allocation.
SELECT coalesce(max(c.revision),0)::bigint AS revision FROM document_package_captures_v1 c
WHERE c.package_id=sqlc.arg(package_id)::uuid AND c.org_id=sqlc.arg(org_id)::uuid AND c.document_id=sqlc.arg(document_id)::uuid;

-- name: AppendDocumentPackageCaptureV1 :one
-- The immutable ManifestV1 bridge supplies these bytes and both hashes together.
-- This query is persistence only; the caller owns authorization and admission.
WITH root AS MATERIALIZED (
 SELECT d.id FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz AND d.status='draft' AND d.deleted_at IS NULL FOR UPDATE
), locked AS MATERIALIZED (
 SELECT p.id FROM document_packages_v1 p JOIN root ON root.id=p.document_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid
 AND p.draft_generation=sqlc.arg(expected_generation)::bigint FOR UPDATE OF p
)
INSERT INTO document_package_captures_v1(package_id,org_id,document_id,revision,previous_revision,captured_root_updated_at,captured_draft_generation,
 manifest,manifest_sha256,legal_commitment_sha256,created_by)
SELECT locked.id,sqlc.arg(org_id)::uuid,sqlc.arg(document_id)::uuid,sqlc.arg(revision)::bigint,sqlc.arg(expected_previous_revision)::bigint,
 sqlc.arg(expected_updated_at)::timestamptz,sqlc.arg(expected_generation)::bigint,sqlc.arg(manifest)::bytea,sqlc.arg(manifest_sha256)::bytea,
 sqlc.arg(legal_commitment_sha256)::bytea,sqlc.arg(created_by)::uuid FROM locked RETURNING *;

-- name: GetDocumentPackageCaptureHeaderV1 :one
-- Fixed scalar header precedes payload/member allocation. This is historical
-- identity, not today's editable root clock or attachment generation.
SELECT package_id,org_id,document_id,revision,previous_revision,captured_root_updated_at,captured_draft_generation,
 octet_length(manifest)::integer AS manifest_bytes,manifest_sha256,legal_commitment_sha256,member_count,pdf_bytes,pdf_pages,created_by,created_at
FROM document_package_captures_v1 WHERE package_id=sqlc.arg(package_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND document_id=sqlc.arg(document_id)::uuid AND revision=sqlc.arg(revision)::bigint;

-- name: GetDocumentPackageCapturePayloadV1 :one
-- Owner validates trusted header bounds and retains that exact binding/hash.
SELECT manifest FROM document_package_captures_v1 WHERE package_id=sqlc.arg(package_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND document_id=sqlc.arg(document_id)::uuid AND revision=sqlc.arg(revision)::bigint
 AND manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND octet_length(manifest)=sqlc.arg(expected_manifest_bytes)::integer AND octet_length(manifest) BETWEEN 1 AND 65536;

-- name: ListDocumentPackageCaptureMembersV1 :many
-- Prepay<=17 actual bounded report bodies plus typed/array/wire overlap before
-- reading members. NULL report pairs identify historical, unverified rows.
SELECT m.package_id,m.revision,m.org_id,m.member_position,m.member_document_id,m.title,m.category,m.pdf_key,m.pdf_version_id,m.pdf_sha256,m.pdf_bytes,m.pdf_pages,m.source_kind,m.source_commitment,m.origin_commitment,m.materialization_id,m.materialization_sequence,m.pdf_intake_report,m.pdf_intake_report_sha256 FROM document_package_capture_members_v1 m JOIN document_package_captures_v1 c
 ON c.package_id=m.package_id AND c.revision=m.revision AND c.org_id=m.org_id
WHERE c.package_id=sqlc.arg(package_id)::uuid AND c.org_id=sqlc.arg(org_id)::uuid AND c.document_id=sqlc.arg(document_id)::uuid
 AND c.revision=sqlc.arg(revision)::bigint AND c.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
 AND c.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea AND c.member_count=sqlc.arg(expected_member_count)::smallint
ORDER BY m.member_position LIMIT 18;
