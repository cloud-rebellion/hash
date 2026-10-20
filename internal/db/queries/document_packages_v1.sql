-- name: CreateDocumentPackageV1 :one
WITH root AS MATERIALIZED (
 SELECT id FROM documents WHERE id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND status='draft' AND deleted_at IS NULL AND updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND source_kind='pdf' AND NOT is_envelope AND parent_envelope_id IS NULL FOR UPDATE
)
INSERT INTO document_packages_v1(id,document_id,org_id,created_by)
SELECT sqlc.arg(package_id)::uuid,root.id,sqlc.arg(org_id)::uuid,sqlc.arg(created_by)::uuid FROM root
RETURNING *;

-- name: LockDocumentPackageV1 :one
-- Native caller has already admitted and locked actual root/source headers.
SELECT p.* FROM document_packages_v1 p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id
WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
FOR UPDATE OF d,p;

-- name: CountDocumentAttachmentDraftsV1 :one
SELECT count(*)::bigint FROM document_attachment_drafts_v1
WHERE package_id=sqlc.arg(package_id)::uuid AND org_id=sqlc.arg(org_id)::uuid;

-- name: LockDocumentPackageByRootV1 :one
-- The genuine paired native owner already holds the root/new-source document
-- locks in global UUID order. This takes no old immutable member source lock.
SELECT p.id,p.document_id,p.org_id,p.draft_generation,p.created_by,p.created_at
FROM document_packages_v1 p
WHERE p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid
FOR UPDATE OF p;

-- name: GetDocumentPackageDraftSizesV1 :one
-- Scalar inventory only. Bound package presence/generation is not an empty
-- aggregate on a missing/stale header. No report serialization or live source
-- join occurs; the actual root/package locks hold through the later body read.
WITH bound AS MATERIALIZED (
 SELECT id,document_id,org_id,draft_generation FROM document_packages_v1
 WHERE id=sqlc.arg(package_id)::uuid AND document_id=sqlc.arg(document_id)::uuid
 AND org_id=sqlc.arg(org_id)::uuid AND draft_generation=sqlc.arg(expected_generation)::bigint
)
SELECT p.id AS package_id,p.document_id,p.org_id,p.draft_generation,
 a.member_count,a.raw_text_bytes,a.report_bytes,a.missing_reports,a.pdf_bytes,a.pdf_pages
FROM bound p CROSS JOIN LATERAL (
 SELECT count(*)::bigint AS member_count,
 coalesce(sum(octet_length(title)+octet_length(category)+octet_length(pdf_key)+octet_length(pdf_version_id)
  +octet_length(pdf_sha256)+octet_length(source_kind)+coalesce(octet_length(source_commitment),0)
  +coalesce(octet_length(origin_commitment),0)+coalesce(octet_length(pdf_intake_report_sha256),0)),0)::bigint AS raw_text_bytes,
 coalesce(sum(octet_length(pdf_intake_report)),0)::bigint AS report_bytes,
 count(*) FILTER(WHERE pdf_intake_report IS NULL)::bigint AS missing_reports,
 coalesce(sum(pdf_bytes),0)::bigint AS pdf_bytes,coalesce(sum(pdf_pages),0)::bigint AS pdf_pages
 FROM document_attachment_drafts_v1 a WHERE a.package_id=p.id AND a.org_id=p.org_id
) a;

-- name: TryDocumentPackageMemberPrivacyFenceV1 :one
-- A fresh pending-request statement MUST follow this nonblocking shared fence.
-- M102's matching DSR trigger protects creation, moves and reopen transitions.
SELECT hash_try_document_package_privacy_fence_v1(sqlc.arg(org_id)::uuid,sqlc.arg(document_id)::uuid)::boolean AS acquired;

-- name: ListDocumentPackageDraftSubjectsV1 :many
-- UUID/scalar inventory before privacy policy and any retained report body.
-- Native root/package locks and the actual count<=16 precede this allocation.
SELECT a.member_document_id,a.ordinal FROM document_attachment_drafts_v1 a
JOIN document_packages_v1 p ON p.id=a.package_id AND p.org_id=a.org_id
WHERE p.id=sqlc.arg(package_id)::uuid AND p.document_id=sqlc.arg(document_id)::uuid
AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint
ORDER BY a.ordinal LIMIT 17;

-- name: HasDocumentPackageDraftMembersV1 :one
-- The paired native owner holds this candidate's document lock; empty package
-- headers/captures are allowed, but nesting selected draft annexes is not.
SELECT EXISTS(SELECT 1 FROM document_packages_v1 p JOIN document_attachment_drafts_v1 a ON a.package_id=p.id AND a.org_id=p.org_id
 WHERE p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid) AS present;

-- name: ListDocumentAttachmentDraftsV1 :many
-- Count<=16 and same-generation/root locking precede allocation in the owner.
-- Fixed LIMIT is an additional bound, never caller-controlled pagination.
-- M101 report bytes (each<=64KiB) and exact row/array/wire overlap must also
-- be prepaid by the owned reader; these rows are not admission authority.
SELECT a.package_id,a.org_id,a.member_document_id,a.ordinal,a.title,a.category,a.pdf_key,a.pdf_version_id,a.pdf_sha256,a.pdf_bytes,a.pdf_pages,a.source_kind,a.source_commitment,a.origin_commitment,a.materialization_id,a.materialization_sequence,a.created_at,a.pdf_intake_report,a.pdf_intake_report_sha256 FROM document_attachment_drafts_v1 a JOIN document_packages_v1 p ON p.id=a.package_id AND p.org_id=a.org_id
WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint
ORDER BY a.ordinal LIMIT 17;

-- name: InsertDocumentAttachmentDraftV1 :one
WITH identities AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_packages_v1 p ON p.org_id=d.org_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid
 AND d.id IN (p.document_id,sqlc.arg(member_document_id)::uuid)
 ORDER BY d.id FOR UPDATE OF d
), locked AS MATERIALIZED (
 SELECT p.id FROM document_packages_v1 p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint
 AND d.status='draft' AND d.deleted_at IS NULL AND (SELECT count(*) FROM identities)=2 FOR UPDATE OF p
)
INSERT INTO document_attachment_drafts_v1(package_id,org_id,member_document_id,ordinal,title,category,
 pdf_key,pdf_version_id,pdf_sha256,pdf_bytes,pdf_pages,source_kind,source_commitment,origin_commitment,materialization_id,materialization_sequence)
SELECT locked.id,sqlc.arg(org_id)::uuid,sqlc.arg(member_document_id)::uuid,sqlc.arg(ordinal)::smallint,sqlc.arg(title)::text,sqlc.arg(category)::text,
 sqlc.arg(pdf_key)::text,sqlc.arg(pdf_version_id)::text,sqlc.arg(pdf_sha256)::bytea,sqlc.arg(pdf_bytes)::bigint,sqlc.arg(pdf_pages)::integer,
 sqlc.arg(source_kind)::text,sqlc.narg(source_commitment)::bytea,sqlc.narg(origin_commitment)::bytea,sqlc.narg(materialization_id)::uuid,sqlc.narg(materialization_sequence)::integer
FROM locked RETURNING package_id,org_id,member_document_id,ordinal,title,category,pdf_key,pdf_version_id,pdf_sha256,pdf_bytes,pdf_pages,source_kind,source_commitment,origin_commitment,materialization_id,materialization_sequence,created_at,pdf_intake_report,pdf_intake_report_sha256;

-- name: UpdateDocumentAttachmentLabelsV1 :one
WITH root AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND d.status='draft' AND d.deleted_at IS NULL FOR UPDATE OF d
), locked AS MATERIALIZED (
 SELECT p.id FROM document_packages_v1 p JOIN root ON root.id=p.document_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint FOR UPDATE OF p
)
UPDATE document_attachment_drafts_v1 a SET ordinal=sqlc.arg(ordinal)::smallint,title=sqlc.arg(title)::text,category=sqlc.arg(category)::text
FROM locked WHERE a.package_id=locked.id AND a.org_id=sqlc.arg(org_id)::uuid AND a.member_document_id=sqlc.arg(member_document_id)::uuid RETURNING a.package_id,a.org_id,a.member_document_id,a.ordinal,a.title,a.category,a.pdf_key,a.pdf_version_id,a.pdf_sha256,a.pdf_bytes,a.pdf_pages,a.source_kind,a.source_commitment,a.origin_commitment,a.materialization_id,a.materialization_sequence,a.created_at,a.pdf_intake_report,a.pdf_intake_report_sha256;

-- name: DeleteDocumentAttachmentDraftV1 :execrows
WITH root AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND d.status='draft' AND d.deleted_at IS NULL FOR UPDATE OF d
), locked AS MATERIALIZED (
 SELECT p.id FROM document_packages_v1 p JOIN root ON root.id=p.document_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint FOR UPDATE OF p
)
DELETE FROM document_attachment_drafts_v1 a USING locked WHERE a.package_id=locked.id AND a.org_id=sqlc.arg(org_id)::uuid AND a.member_document_id=sqlc.arg(member_document_id)::uuid;

-- name: DeleteEmptyDocumentPackageV1 :execrows
WITH root AS MATERIALIZED (
 SELECT d.id FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND d.status='draft' FOR UPDATE OF d
)
DELETE FROM document_packages_v1 p USING root WHERE p.document_id=root.id AND p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid
 AND p.draft_generation=sqlc.arg(expected_generation)::bigint AND NOT EXISTS(SELECT 1 FROM document_attachment_drafts_v1 a WHERE a.package_id=p.id)
 AND NOT EXISTS(SELECT 1 FROM document_package_captures_v1 c WHERE c.package_id=p.id);

-- name: GetDocumentPackageMutationClockV1 :one
-- Separate statement after trigger-bearing writes. INSERT RETURNING and a
-- base-table CTE in that statement do not prove the new trigger-updated clock.
SELECT d.id AS document_id,d.org_id,d.updated_at,p.id AS package_id,p.draft_generation
FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
WHERE p.id=sqlc.arg(package_id)::uuid AND d.id=sqlc.arg(document_id)::uuid
AND d.org_id=sqlc.arg(org_id)::uuid;

-- name: InsertOwnedDocumentAttachmentV1 :one
-- Actual paired native locks, original policy and funded immutable snapshots
-- already exist. No live old-member join, lock acquisition or caller pin DTO.
WITH bound AS MATERIALIZED (
 SELECT p.id FROM document_packages_v1 p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.document_id=sqlc.arg(document_id)::uuid
 AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint
 AND p.draft_generation<9223372036854775807 AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND d.status='draft' AND d.deleted_at IS NULL AND d.source_kind='pdf' AND NOT d.is_envelope AND d.parent_envelope_id IS NULL
 AND (SELECT count(*) FROM document_attachment_drafts_v1 a WHERE a.package_id=p.id AND a.org_id=p.org_id)<16
 AND NOT EXISTS(SELECT 1 FROM document_attachment_drafts_v1 a WHERE a.package_id=p.id AND a.org_id=p.org_id AND a.ordinal=sqlc.arg(ordinal)::smallint)
 FOR UPDATE OF p
)
INSERT INTO document_attachment_drafts_v1(package_id,org_id,member_document_id,ordinal,title,category,
 pdf_key,pdf_version_id,pdf_sha256,pdf_bytes,pdf_pages,source_kind,source_commitment,origin_commitment,
 materialization_id,materialization_sequence,pdf_intake_report,pdf_intake_report_sha256)
SELECT bound.id,sqlc.arg(org_id)::uuid,sqlc.arg(member_document_id)::uuid,sqlc.arg(ordinal)::smallint,
 sqlc.arg(title)::text,sqlc.arg(category)::text,sqlc.arg(pdf_key)::text,sqlc.arg(pdf_version_id)::text,
 sqlc.arg(pdf_sha256)::bytea,sqlc.arg(pdf_bytes)::bigint,sqlc.arg(pdf_pages)::integer,sqlc.arg(source_kind)::text,
 sqlc.narg(source_commitment)::bytea,sqlc.narg(origin_commitment)::bytea,
 sqlc.narg(materialization_id)::uuid,sqlc.narg(materialization_sequence)::integer,
 sqlc.arg(pdf_intake_report)::bytea,sqlc.arg(pdf_intake_report_sha256)::bytea
FROM bound RETURNING member_document_id;

-- name: ListDocumentPackageAttachmentMetadataV1 :many
-- Root/package locks, scalar row/text bounds and every privacy fence precede
-- this view. No current old-source join, report body or storage key is exposed.
SELECT a.member_document_id,a.ordinal,a.title,a.category,a.pdf_version_id,a.pdf_sha256,a.pdf_bytes,a.pdf_pages
FROM document_attachment_drafts_v1 a JOIN document_packages_v1 p ON p.id=a.package_id AND p.org_id=a.org_id
WHERE p.id=sqlc.arg(package_id)::uuid AND p.document_id=sqlc.arg(document_id)::uuid
AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint
ORDER BY a.ordinal LIMIT 17;


-- name: ApplyOwnedDocumentAttachmentLayoutV1 :one
-- The fixed native root owner has already read the actual selected membership,
-- checked the exact subset/order/labels and fenced every selected subject.
WITH root AS MATERIALIZED (
 SELECT d.id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND d.status='draft' AND d.deleted_at IS NULL AND d.source_kind='pdf'
 AND NOT d.is_envelope AND d.parent_envelope_id IS NULL FOR UPDATE OF d
), locked AS MATERIALIZED (
 SELECT p.id FROM document_packages_v1 p JOIN root ON root.id=p.document_id
 WHERE p.id=sqlc.arg(package_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid
 AND p.draft_generation=sqlc.arg(expected_generation)::bigint FOR UPDATE OF p
), desired AS MATERIALIZED (
 SELECT id,(sqlc.arg(titles)::text[])[position] AS title,
 (sqlc.arg(categories)::text[])[position] AS category,position::smallint AS ordinal
 FROM unnest(sqlc.arg(member_ids)::uuid[]) WITH ORDINALITY AS x(id,position)
), removed AS (
 DELETE FROM document_attachment_drafts_v1 a USING locked
 WHERE a.package_id=locked.id AND a.org_id=sqlc.arg(org_id)::uuid
 AND NOT (a.member_document_id=ANY(sqlc.arg(member_ids)::uuid[])) RETURNING a.member_document_id
), changed AS (
 UPDATE document_attachment_drafts_v1 a SET ordinal=x.ordinal,title=x.title,category=x.category
 FROM locked,desired x WHERE a.package_id=locked.id AND a.org_id=sqlc.arg(org_id)::uuid
 AND a.member_document_id=x.id
 AND ROW(a.ordinal,a.title,a.category) IS DISTINCT FROM ROW(x.ordinal,x.title,x.category)
 RETURNING a.member_document_id
)
SELECT ((SELECT count(*) FROM removed)+(SELECT count(*) FROM changed))::bigint AS changed_rows;

-- name: GetDocumentPackageAttachmentPreviewPinV1 :one
-- Private bounded pin only, after native root policy and same-transaction
-- inventory/count/privacy fences. Never joins the mutable member source.
SELECT a.pdf_key,a.pdf_version_id,a.pdf_sha256,a.pdf_bytes,a.pdf_pages
FROM document_attachment_drafts_v1 a JOIN document_packages_v1 p ON p.id=a.package_id AND p.org_id=a.org_id
WHERE p.id=sqlc.arg(package_id)::uuid AND p.document_id=sqlc.arg(document_id)::uuid
AND p.org_id=sqlc.arg(org_id)::uuid AND p.draft_generation=sqlc.arg(expected_generation)::bigint
AND a.member_document_id=sqlc.arg(member_document_id)::uuid;
