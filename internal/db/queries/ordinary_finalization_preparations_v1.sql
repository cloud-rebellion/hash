-- Metadata precedes every bounded native body read; no provider write precedes
-- a complete immutable original four-output plan.
-- name: CaptureOrdinaryFinalizationPreparationV1 :execrows
INSERT INTO document_ordinary_finalization_preparations_v1(document_id,org_id,mode,completion_effective_at,cutoff,retain_until,final_pdf_sha256,report_schema)
SELECT d.id,d.org_id,sqlc.arg(mode)::text,d.completion_effective_at,d.updated_at,d.finalization_retain_until,sqlc.arg(final_pdf_sha256)::bytea,d.participant_report_schema
FROM documents d WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid AND d.status='finalizing'
AND d.completion_effective_at=sqlc.arg(completion_effective_at)::timestamptz AND d.updated_at=sqlc.arg(cutoff)::timestamptz
ON CONFLICT(document_id) DO NOTHING;

-- name: GetOrdinaryFinalizationPreparationHeaderV1 :one
SELECT p.document_id,p.org_id,p.report_schema,p.mode,p.completion_effective_at,p.cutoff,p.retain_until,p.final_pdf_sha256,
p.certificate_render_sha256,COALESCE(octet_length(p.certificate_render_html),0)::bigint AS render_html_bytes,
p.report_cutoff,p.history_rows,p.report_sha256,p.staged_at,p.published_at,p.bodies_retired_at,p.certificate_input_frozen
FROM document_ordinary_finalization_preparations_v1 p
WHERE p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid;

-- name: FreezeOrdinaryFinalizationCertificateInputV1 :execrows
UPDATE document_ordinary_finalization_preparations_v1 p SET certificate_render_html=sqlc.arg(render_html)::bytea,
certificate_render_sha256=digest(sqlc.arg(render_html)::bytea,'sha256'),report_cutoff=sqlc.arg(report_cutoff)::timestamptz,
history_rows=sqlc.arg(history_rows)::bigint,report_sha256=sqlc.arg(report_sha256)::bytea,certificate_input_frozen=TRUE
WHERE p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND NOT p.certificate_input_frozen AND p.staged_at IS NULL
AND p.report_schema=sqlc.arg(report_schema)::text
AND EXISTS(SELECT 1 FROM documents d WHERE d.id=p.document_id AND d.org_id=p.org_id AND d.participant_report_schema=p.report_schema);

-- name: CaptureOrdinaryFinalizationOutputV1 :execrows
INSERT INTO document_ordinary_finalization_outputs_v1(document_id,org_id,kind,storage_key,sha256,bytes,content_type,payload)
VALUES(sqlc.arg(document_id)::uuid,sqlc.arg(org_id)::uuid,sqlc.arg(kind)::text,sqlc.arg(storage_key)::text,
digest(sqlc.arg(payload)::bytea,'sha256'),octet_length(sqlc.arg(payload)::bytea),sqlc.arg(content_type)::text,sqlc.arg(payload)::bytea)
ON CONFLICT(document_id,kind) DO NOTHING;

-- name: ListOrdinaryFinalizationOutputHeadersV1 :many
SELECT document_id,org_id,kind,storage_key,sha256,bytes,content_type,version_id,verified_at
FROM document_ordinary_finalization_outputs_v1 WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
ORDER BY CASE kind WHEN 'final_pdf' THEN 0 WHEN 'certificate_pdf' THEN 1 WHEN 'certificate_payload' THEN 2 ELSE 3 END;

-- name: ReadOrdinaryFinalizationOutputBodyV1 :one
SELECT payload FROM document_ordinary_finalization_outputs_v1
WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND kind=sqlc.arg(kind)::text
AND bytes=sqlc.arg(expected_bytes)::bigint AND sha256=sqlc.arg(expected_sha256)::bytea;

-- name: ReadOrdinaryFinalizationRenderHTMLV1 :one
SELECT certificate_render_html FROM document_ordinary_finalization_preparations_v1
WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
AND octet_length(certificate_render_html)=sqlc.arg(expected_bytes)::bigint AND certificate_render_sha256=sqlc.arg(expected_sha256)::bytea;

-- name: PinOrdinaryFinalizationOutputVersionV1 :execrows
UPDATE document_ordinary_finalization_outputs_v1 SET version_id=sqlc.arg(version_id)::text
WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND kind=sqlc.arg(kind)::text
AND sha256=sqlc.arg(expected_sha256)::bytea AND version_id IS NULL;

-- name: VerifyOrdinaryFinalizationOutputVersionV1 :execrows
UPDATE document_ordinary_finalization_outputs_v1 SET verified_at=clock_timestamp()
WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND kind=sqlc.arg(kind)::text
AND sha256=sqlc.arg(expected_sha256)::bytea AND version_id=sqlc.arg(version_id)::text AND verified_at IS NULL;

-- name: MarkOrdinaryFinalizationPreparationStagedV1 :execrows
UPDATE document_ordinary_finalization_preparations_v1 p SET staged_at=clock_timestamp()
WHERE p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.staged_at IS NULL
AND p.certificate_input_frozen
AND (SELECT count(*) FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=p.document_id AND o.org_id=p.org_id AND o.verified_at IS NOT NULL AND o.version_id IS NOT NULL)=4
AND EXISTS(SELECT 1 FROM document_finalization_intents i WHERE i.document_id=p.document_id AND i.org_id=p.org_id AND i.completion_effective_at=p.completion_effective_at);

-- name: MarkOrdinaryFinalizationPreparationPublishedV1 :execrows
UPDATE document_ordinary_finalization_preparations_v1 p SET published_at=clock_timestamp()
WHERE p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.staged_at IS NOT NULL AND p.published_at IS NULL
AND EXISTS(SELECT 1 FROM documents d WHERE d.id=p.document_id AND d.org_id=p.org_id AND d.status='completed' AND d.completion_effective_at=p.completion_effective_at
AND d.final_pdf_sha=p.final_pdf_sha256);

-- name: RetirePublishedOrdinaryFinalizationRenderHTMLV1 :execrows
UPDATE document_ordinary_finalization_preparations_v1 p SET certificate_render_html=NULL,bodies_retired_at=clock_timestamp()
WHERE p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.published_at IS NOT NULL AND p.bodies_retired_at IS NULL;

-- name: RetirePublishedOrdinaryFinalizationBodiesV1 :execrows
UPDATE document_ordinary_finalization_outputs_v1 o SET payload=NULL
FROM document_ordinary_finalization_preparations_v1 p WHERE o.document_id=p.document_id AND o.org_id=p.org_id
AND p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.published_at IS NOT NULL AND p.bodies_retired_at IS NOT NULL;

-- name: DeleteExpiredOrdinaryFinalizationOutputsV1 :execrows
-- Only a real soft-deletion/retention owner may use this after its locked root
-- check. Expiry never authorizes a new response, replacement or publication.
DELETE FROM document_ordinary_finalization_outputs_v1 o USING document_ordinary_finalization_preparations_v1 p,documents d
WHERE o.document_id=p.document_id AND o.org_id=p.org_id AND d.id=p.document_id AND d.org_id=p.org_id
AND p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid AND p.retain_until<clock_timestamp() AND d.deleted_at IS NOT NULL
AND NOT EXISTS(SELECT 1 FROM data_subject_requests r WHERE r.org_id=d.org_id AND (r.document_id=d.id OR r.document_id IS NULL) AND r.status IN('open','in_progress'));

-- name: DeleteExpiredOrdinaryFinalizationPreparationV1 :execrows
DELETE FROM document_ordinary_finalization_preparations_v1 p USING documents d
WHERE d.id=p.document_id AND d.org_id=p.org_id AND p.document_id=sqlc.arg(document_id)::uuid AND p.org_id=sqlc.arg(org_id)::uuid
AND p.retain_until<clock_timestamp() AND d.deleted_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=p.document_id)
AND NOT EXISTS(SELECT 1 FROM data_subject_requests r WHERE r.org_id=d.org_id AND (r.document_id=d.id OR r.document_id IS NULL) AND r.status IN('open','in_progress'));
