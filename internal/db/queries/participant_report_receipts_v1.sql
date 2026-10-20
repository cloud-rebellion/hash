-- name: InsertParticipantReportReceiptV1 :execrows
INSERT INTO document_participant_reports_v1(document_id,org_id,completion_effective_at,schema_version,cutoff,history_rows,report_sha256,final_pdf_sha256,audit_cert_sha256,audit_payload_sha256,audit_signature_sha256)
VALUES(sqlc.arg(document_id)::uuid,sqlc.arg(org_id)::uuid,sqlc.arg(completion_effective_at)::timestamptz,sqlc.arg(report_schema)::text,sqlc.arg(cutoff)::timestamptz,sqlc.arg(history_rows)::bigint,sqlc.arg(report_sha256)::bytea,sqlc.arg(final_pdf_sha256)::bytea,sqlc.arg(audit_cert_sha256)::bytea,sqlc.arg(audit_payload_sha256)::bytea,sqlc.arg(audit_signature_sha256)::bytea)
ON CONFLICT DO NOTHING;

-- name: ParticipantReportReceiptMatchesV1 :one
SELECT EXISTS(SELECT 1 FROM document_participant_reports_v1 WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND EXISTS(SELECT 1 FROM documents d WHERE d.id=document_participant_reports_v1.document_id AND d.org_id=document_participant_reports_v1.org_id AND d.participant_report_schema=document_participant_reports_v1.schema_version) AND completion_effective_at=sqlc.arg(completion_effective_at)::timestamptz AND schema_version=sqlc.arg(report_schema)::text AND cutoff=sqlc.arg(cutoff)::timestamptz AND history_rows=sqlc.arg(history_rows)::bigint AND report_sha256=sqlc.arg(report_sha256)::bytea AND final_pdf_sha256=sqlc.arg(final_pdf_sha256)::bytea AND audit_cert_sha256=sqlc.arg(audit_cert_sha256)::bytea AND audit_payload_sha256=sqlc.arg(audit_payload_sha256)::bytea AND audit_signature_sha256=sqlc.arg(audit_signature_sha256)::bytea)::boolean;

-- name: InsertParticipantReportDeliveryV1 :execrows
INSERT INTO document_participant_report_deliveries_v1(document_id,org_id,completion_effective_at,audience,recipient_id,email_delivery_id,message_sha256,final_pdf_sha256,audit_cert_sha256)
SELECT d.id,d.org_id,d.completion_effective_at,sqlc.arg(audience)::text,sqlc.arg(recipient_id)::uuid,e.id,hash_package_send_message_sha256_v1(e.id),d.final_pdf_sha,d.audit_cert_sha256 FROM documents d JOIN email_deliveries e ON e.id=sqlc.arg(email_delivery_id)::uuid
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.status='completed'
AND EXISTS(SELECT 1 FROM document_participant_reports_v1 r WHERE r.document_id=d.id AND r.org_id=d.org_id AND r.completion_effective_at=d.completion_effective_at AND r.schema_version=d.participant_report_schema);
