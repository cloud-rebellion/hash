-- name: GetDocumentPackageResponseVersionV1 :one
SELECT hash_package_response_version_v1()::integer AS version;

-- name: ListSignerPackageResponseBindingV1 :many
-- The native caller owns the genuine original reader and takes this root lock
-- before its recipient lock. LIMIT2 detects ambiguity instead of choosing a
-- latest capture. The token digest is an original-credential observation.
WITH root AS MATERIALIZED (
 SELECT d.id,d.org_id,d.sent_at FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 FOR UPDATE NOWAIT
), party AS MATERIALIZED (
 SELECT r.* FROM recipients r JOIN root ON root.id=r.document_id
 WHERE r.id=sqlc.arg(recipient_id)::uuid FOR UPDATE OF r NOWAIT
)
SELECT a.attempt_id,a.package_id,a.capture_revision,a.manifest_sha256,a.legal_commitment_sha256,
 root.sent_at,a.article13_notice_epoch_at,a.retain_until,a.member_count,
 hash_package_incorporation_version_v1()::text AS incorporation_version,
 hash_package_incorporation_text_v1()::text AS incorporation_text,
 hash_package_incorporation_sha256_v1()::bytea AS incorporation_sha256
FROM root JOIN document_package_send_attempts_v1 a ON a.org_id=root.org_id AND a.document_id=root.id
JOIN party r ON r.document_id=root.id
JOIN document_package_send_initial_invite_receipts_v1 i ON i.attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id AND i.recipient_id=r.id
WHERE r.magic_token_hash=sqlc.arg(token_hash)::bytea
 AND hash_package_response_binding_matches_v1(a.attempt_id,a.org_id,a.document_id)
ORDER BY a.attempt_id LIMIT 2;

-- name: RecordDocumentPackageResponseV1 :one
-- Actual native audit ownership supplies its emitted event ID; SQL reads the
-- real row/hash/time. Caller digests only compare the admitted observation.
-- No arbitrary JSON, provider keys or caller-supplied audit hashes enter here.
WITH root AS MATERIALIZED (
 SELECT d.id,d.org_id,d.sent_at FROM documents d
 WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 FOR UPDATE NOWAIT
), party AS MATERIALIZED (
 SELECT r.id,r.document_id FROM recipients r JOIN root ON root.id=r.document_id
 WHERE r.id=sqlc.arg(recipient_id)::uuid FOR UPDATE OF r NOWAIT
)
INSERT INTO document_package_responses_v1(attempt_id,org_id,document_id,recipient_id,package_id,capture_revision,
 manifest_sha256,legal_commitment_sha256,sent_at,article13_notice_epoch_at,incorporation_version,incorporation_sha256,
 response_kind,signature_id,response_event_id,response_event_row_sha256,response_event_created_at)
SELECT a.attempt_id,a.org_id,a.document_id,party.id,a.package_id,a.capture_revision,
 a.manifest_sha256,a.legal_commitment_sha256,root.sent_at,a.article13_notice_epoch_at,
 hash_package_incorporation_version_v1(),hash_package_incorporation_sha256_v1(),
 CASE WHEN e.kind='document.signed' THEN 'signed' ELSE 'accepted' END,
 sqlc.narg(signature_id)::uuid,e.id,e.row_hash,e.created_at
FROM root JOIN party ON party.document_id=root.id
JOIN document_package_send_attempts_v1 a ON a.org_id=root.org_id AND a.document_id=root.id
JOIN events e ON e.id=sqlc.arg(response_event_id)::uuid AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.recipient_id=party.id
WHERE a.attempt_id=sqlc.arg(attempt_id)::uuid
 AND a.manifest_sha256=sqlc.arg(expected_manifest_sha256)::bytea
 AND a.legal_commitment_sha256=sqlc.arg(expected_legal_commitment_sha256)::bytea
 AND e.kind IN ('document.signed','document.accepted')
 AND hash_package_response_binding_matches_v1(a.attempt_id,a.org_id,a.document_id)
RETURNING *;

-- name: InspectDocumentPackageResponseV1 :one
-- Historical scalar evidence remains independently readable after credential
-- rotation or lawful recipient/display-payload redaction. It does not grant
-- response authority; a retry still validates its own original reader.
SELECT * FROM document_package_responses_v1
WHERE org_id=sqlc.arg(org_id)::uuid AND document_id=sqlc.arg(document_id)::uuid
 AND recipient_id=sqlc.arg(recipient_id)::uuid AND attempt_id=sqlc.arg(attempt_id)::uuid;

-- name: GetDocumentPackageResponseV1 :many
-- An ambiguous historical epoch is never treated as an identical retry.
SELECT * FROM document_package_responses_v1
WHERE org_id=sqlc.arg(org_id)::uuid AND document_id=sqlc.arg(document_id)::uuid
 AND recipient_id=sqlc.arg(recipient_id)::uuid
ORDER BY article13_notice_epoch_at,attempt_id LIMIT 2;

-- name: MatchDocumentPackageSignedRetryV1 :one
-- Return only a fixed scalar. The actual native prepared request supplies its
-- owned name/font, and the immutable response receipt supplies exact row IDs.
SELECT EXISTS(
 SELECT 1 FROM document_package_responses_v1 x
 JOIN signatures s ON s.id=x.signature_id AND s.document_id=x.document_id AND s.recipient_id=x.recipient_id
 JOIN events e ON e.id=x.response_event_id AND e.org_id=x.org_id AND e.document_id=x.document_id AND e.recipient_id=x.recipient_id
 WHERE x.attempt_id=sqlc.arg(attempt_id)::uuid AND x.org_id=sqlc.arg(org_id)::uuid
 AND x.document_id=sqlc.arg(document_id)::uuid AND x.recipient_id=sqlc.arg(recipient_id)::uuid
 AND x.signature_id=sqlc.arg(signature_id)::uuid AND s.font=sqlc.arg(expected_font)::text AND s.typed_name=sqlc.arg(expected_typed_name)::text
 AND x.response_event_id=sqlc.arg(response_event_id)::uuid AND x.response_event_row_sha256=sqlc.arg(response_event_row_sha256)::bytea
 AND e.row_hash=x.response_event_row_sha256)::boolean AS matched;
