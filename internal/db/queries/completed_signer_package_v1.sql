-- name: ListCompletedSignerPackageReadBindingV1 :many
-- Original reader scope and artifact pins come only from the genuine native
-- Completed constructor. This query never admits an active ceremony token.
SELECT a.attempt_id,a.package_id
FROM documents d JOIN recipients r ON r.document_id=d.id
JOIN document_package_send_attempts_v1 a ON a.document_id=d.id AND a.org_id=d.org_id
JOIN document_package_responses_v1 x ON x.attempt_id=a.attempt_id AND x.org_id=a.org_id AND x.document_id=a.document_id AND x.recipient_id=r.id
JOIN document_participant_reports_v1 p ON p.document_id=d.id AND p.org_id=d.org_id AND p.completion_effective_at=d.completion_effective_at
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.deleted_at IS NULL
 AND r.id=sqlc.arg(recipient_id)::uuid AND r.magic_token_hash=sqlc.arg(token_hash)::bytea
 AND r.status IN ('signed','accepted') AND r.magic_token_expires_at>clock_timestamp()
 AND d.status='completed' AND d.source_kind='pdf' AND NOT d.is_envelope AND d.parent_envelope_id IS NULL
 AND d.completion_effective_at=sqlc.arg(completion_effective_at)::timestamptz
 AND d.final_pdf_key=sqlc.arg(final_pdf_key)::text AND d.final_pdf_version_id=sqlc.arg(final_pdf_version_id)::text AND d.final_pdf_sha=sqlc.arg(final_pdf_sha256)::bytea
 AND d.audit_cert_key=sqlc.arg(audit_cert_key)::text AND d.audit_cert_version_id=sqlc.arg(audit_cert_version_id)::text AND d.audit_cert_sha256=sqlc.arg(audit_cert_sha256)::bytea
 AND d.audit_payload_key=sqlc.arg(audit_payload_key)::text AND d.audit_payload_version_id=sqlc.arg(audit_payload_version_id)::text AND d.audit_payload_sha256=sqlc.arg(audit_payload_sha256)::bytea
 AND d.audit_signature_key=sqlc.arg(audit_signature_key)::text AND d.audit_signature_version_id=sqlc.arg(audit_signature_version_id)::text AND d.audit_signature_sha256=sqlc.arg(audit_signature_sha256)::bytea
 AND p.schema_version=d.participant_report_schema
 AND p.schema_version IN ('hash-participant-report-v1','hash-participant-report-v2') AND octet_length(p.report_sha256)=32
 AND p.final_pdf_sha256=d.final_pdf_sha AND p.audit_cert_sha256=d.audit_cert_sha256
 AND p.audit_payload_sha256=d.audit_payload_sha256 AND p.audit_signature_sha256=d.audit_signature_sha256
 AND x.package_id=a.package_id AND x.capture_revision=a.capture_revision
 AND x.manifest_sha256=a.manifest_sha256 AND x.legal_commitment_sha256=a.legal_commitment_sha256
 AND x.sent_at=d.sent_at AND x.article13_notice_epoch_at=d.article13_notice_epoch_at
 AND hash_package_response_matches_v1(a.attempt_id,r.id)
ORDER BY a.attempt_id LIMIT 2;
