-- name: ListDocumentPackageSendRetentionMembersV1 :many
-- The genuine owner locks the root before receiving bounded immutable pins.
-- No labels, reports, manifest bodies or live annex source rows are read.
WITH root AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid FOR UPDATE NOWAIT
)
SELECT a.attempt_id,a.org_id,a.document_id,a.package_id,a.capture_revision,a.member_count,
 m.member_position,m.member_document_id,m.pdf_key,m.pdf_version_id,m.pdf_sha256,m.pdf_bytes,m.pdf_pages,
 r.provider_namespace_sha256,r.started_at,r.verified_at,r.observed_mode,r.observed_retain_until,r.verifier_profile
FROM root JOIN document_package_send_attempts_v1 a ON a.document_id=root.id AND a.org_id=root.org_id
JOIN document_package_capture_members_v1 m ON m.package_id=a.package_id AND m.revision=a.capture_revision AND m.org_id=a.org_id
LEFT JOIN document_package_send_member_retention_v1 r ON r.attempt_id=a.attempt_id AND r.member_position=m.member_position
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.package_id=sqlc.arg(package_id)::uuid
 AND a.capture_revision=sqlc.arg(capture_revision)::bigint AND a.member_count=sqlc.arg(expected_member_count)::smallint
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
 AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND hash_package_send_member_retention_version_v1()=1
ORDER BY m.member_position LIMIT 18;

-- name: StartDocumentPackageSendMemberRetentionV1 :one
-- Start is persisted together with the genuine exact intent's aggregate start
-- and mirror, before any provider dispatch. Only immutable captured rows mint it.
WITH root AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid FOR UPDATE NOWAIT
), candidate AS MATERIALIZED (
 SELECT a.attempt_id,a.org_id,a.document_id,m.member_position
 FROM root JOIN document_package_send_attempts_v1 a ON a.document_id=root.id AND a.org_id=root.org_id
 JOIN document_package_capture_members_v1 m ON m.package_id=a.package_id AND m.revision=a.capture_revision AND m.org_id=a.org_id
 WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.terminal_outcome IS NULL
  AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
  AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
  AND m.member_position=sqlc.arg(member_position)::smallint AND m.member_position<a.member_count
  AND hash_package_send_member_retention_version_v1()=1
)
INSERT INTO document_package_send_member_retention_v1 AS r(attempt_id,org_id,document_id,member_position,provider_namespace_sha256)
SELECT attempt_id,org_id,document_id,member_position,sqlc.arg(provider_namespace_sha256)::bytea FROM candidate
ON CONFLICT(attempt_id,member_position) DO UPDATE SET started_at=r.started_at
WHERE r.org_id=EXCLUDED.org_id AND r.document_id=EXCLUDED.document_id
 AND r.provider_namespace_sha256=EXCLUDED.provider_namespace_sha256
RETURNING r.*;

-- name: ConfirmDocumentPackageSendMemberRetentionV1 :one
-- Native invocation requires the genuine strict provider result. Fixed literals
-- cannot turn a caller digest/boolean or development read into provider proof.
-- An acknowledged existing verification remains unchanged on a later recheck.
WITH root AS MATERIALIZED (
 SELECT d.id,d.org_id FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid FOR UPDATE NOWAIT
), candidate AS MATERIALIZED (
 SELECT a.attempt_id,a.org_id,a.document_id
 FROM root JOIN document_package_send_attempts_v1 a ON a.document_id=root.id AND a.org_id=root.org_id
 WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.terminal_outcome IS NULL
  AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
  AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
  AND isfinite(sqlc.arg(observed_retain_until)::timestamptz)
  AND sqlc.arg(observed_retain_until)::timestamptz>=a.retain_until
  AND hash_package_send_member_retention_version_v1()=1
)
UPDATE document_package_send_member_retention_v1 r
SET verified_at=COALESCE(r.verified_at,clock_timestamp()),observed_mode=COALESCE(r.observed_mode,'COMPLIANCE'),
 observed_retain_until=COALESCE(r.observed_retain_until,sqlc.arg(observed_retain_until)::timestamptz),
 verifier_profile=COALESCE(r.verifier_profile,'s3-compliance-digest-v1')
FROM candidate a
WHERE r.attempt_id=a.attempt_id AND r.org_id=a.org_id AND r.document_id=a.document_id
 AND r.member_position=sqlc.arg(member_position)::smallint
 AND r.provider_namespace_sha256=sqlc.arg(provider_namespace_sha256)::bytea
RETURNING r.*;

-- name: MarkDocumentPackageMemberRetentionStartedV1 :one
-- The recovery owner already holds the genuine root lock. Keep the original
-- exact-attempt DML while returning no legacy actor or diagnostic TEXT bodies.
UPDATE send_sealing_intents i SET retention_started_at=COALESCE(i.retention_started_at,clock_timestamp()),updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
 AND i.retention_completed_at IS NULL AND hash_package_send_member_retention_version_v1()=1
RETURNING i.document_id,i.org_id,i.package_send_attempt_id,i.retention_started_at,i.retention_completed_at,i.article13_notice_epoch_at,i.retain_until;

-- name: MarkDocumentPackageMemberRetentionCompleteV1 :one
-- M105's database completion guard independently requires every exact member
-- receipt. The original target is retained; no actor/error TEXT is returned.
UPDATE send_sealing_intents i SET retention_completed_at=COALESCE(i.retention_completed_at,clock_timestamp()),
 attempts=i.attempts+1,last_error=NULL,updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid AND a.org_id=sqlc.arg(org_id)::uuid AND a.document_id=sqlc.arg(document_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
 AND i.retention_started_at IS NOT NULL AND hash_package_send_member_retention_version_v1()=1
RETURNING i.document_id,i.org_id,i.package_send_attempt_id,i.retention_started_at,i.retention_completed_at,i.article13_notice_epoch_at,i.retain_until;
