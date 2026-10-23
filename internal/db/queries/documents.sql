-- name: CreateBlocksDocument :one
INSERT INTO documents (org_id, template_id, name, source_kind, blocks_json, variables_json, sender_id, expires_at)
VALUES ($1, $2, $3, 'blocks', $4, $5, $6, $7)
RETURNING *;

-- name: CreatePDFDocument :one
INSERT INTO documents (
    org_id, template_id, name, source_kind,
    pdf_storage_key, pdf_sha256, pdf_storage_version_id,
    evidence_version_pins_required, sender_id, expires_at
)
VALUES ($1, $2, $3, 'pdf', $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetDocument :one
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: GetDocumentForUpdate :one
-- Row-locking read used by the signing engine to serialize concurrent
-- sign/decline/finalize on the same document inside a transaction.
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL FOR UPDATE;

-- name: GetDocumentForShare :one
-- Long-running signer clarification holds a SHARE row lock so revise/resend and
-- every other document mutation wait for one ceremony epoch, while the
-- separately committed request audit and AI-completion audit can still take
-- their foreign-key KEY SHARE locks without self-deadlocking.
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL FOR SHARE;

-- name: GetDocumentByID :one
-- System-level lookup by id alone (no org scope) for the background worker,
-- which holds a document_id (from a reminder row) but not the org. Callers
-- must be system contexts, never request-scoped handlers.
SELECT * FROM documents WHERE id = $1;

-- name: ListDocuments :many
SELECT * FROM documents
WHERE org_id = $1
  AND deleted_at IS NULL
  AND ($2::TEXT[] IS NULL OR status = ANY($2::TEXT[]))
ORDER BY updated_at DESC
LIMIT $3 OFFSET $4;

-- name: ListDocumentsForMCP :many
-- Preserve ordinary document data and cheap current-source pins without copying
-- either embedded approved master/assets into each MCP list row.
SELECT d.id, d.org_id, d.template_id, d.name,
    d.status, d.routing_mode, d.source_kind, d.blocks_json,
    d.variables_json, d.rendered_pdf_key, d.rendered_pdf_sha, d.pdf_storage_key,
    d.pdf_sha256, d.final_pdf_key, d.final_pdf_sha, d.audit_cert_key,
    d.expires_at, d.sent_at, d.completed_at, d.sender_id,
    d.metadata, d.created_at, d.updated_at, d.parent_envelope_id,
    d.envelope_position, d.is_envelope, d.metadata_redaction_report, d.routing_tier,
    d.negotiation_enabled, d.bilingual_target_lang, d.lawful_basis, d.deleted_at,
    d.default_locale, d.requires_signature, d.audit_payload_key, d.audit_payload_sha256,
    d.audit_signature_key, d.audit_signature_sha256, d.pdf_storage_version_id, d.rendered_pdf_version_id,
    d.final_pdf_version_id, d.audit_cert_sha256, d.audit_cert_version_id, d.audit_payload_version_id,
    d.audit_signature_version_id, d.evidence_version_pins_required, d.completion_effective_at, d.completion_effective_at_bound,
    d.finalization_retain_until, d.article13_notice_epoch_at, d.article13_notice_schema, d.article13_notice_epoch_v61_committed,
    NULL::jsonb AS html_source_json, d.html_reviewed_pdf_sha256, d.html_reviewed_by, d.html_reviewed_at,
    d.html_current_materialization_id, NULL::jsonb AS html_current_source_json, d.html_current_page_count, d.html_current_materialization_sequence,
    d.html_reviewed_materialization_id, d.html_effective_source_commitment,
    d.signature_fit_reserved_bytes, d.fits_index_required, d.fits_index_preparation_id, d.fits_index_storage_key,
    d.fits_index_version_id, d.fits_index_sha256, d.fits_index_bytes, d.signature_fit_original_payload_bytes,
    d.signature_fit_original_authority_bytes, d.signature_fit_original_authority_count, d.signing_admission_policy, d.signing_admission_active_id,
    d.signing_admission_sealed_id, d.signing_admission_count, d.signing_admission_static_bytes, d.signing_admission_ordinary_bytes,
    d.signing_admission_plan_bytes, d.signature_fit_request_binding_bytes, d.signature_fit_request_binding_count, d.participant_report_schema
FROM documents d
WHERE d.org_id = $1
  AND d.deleted_at IS NULL
  AND ($2::TEXT[] IS NULL OR d.status = ANY($2::TEXT[]))
ORDER BY d.updated_at DESC
LIMIT $3 OFFSET $4;

-- name: CountDocuments :one
SELECT COUNT(*) FROM documents
WHERE org_id = $1
  AND deleted_at IS NULL
  AND ($2::TEXT[] IS NULL OR status = ANY($2::TEXT[]));

-- name: UpdateDocumentBlocks :one
UPDATE documents
SET blocks_json = $3,
    variables_json = $4,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL AND source_kind = 'blocks'
RETURNING *;

-- name: UpdateDocumentMetadata :one
UPDATE documents
SET name = $3,
    expires_at = $4,
    metadata = $5,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL
RETURNING *;

-- name: SetDocumentHTMLSource :one
-- Set-once provenance for a freshly rendered PDF draft. No caller-controlled
-- generic metadata patch can rewrite this snapshot or inherit prior review.
UPDATE documents
SET html_source_json = sqlc.arg(html_source_json)::jsonb,
    html_reviewed_pdf_sha256 = NULL,
    html_reviewed_by = NULL,
    html_reviewed_at = NULL,
    updated_at = clock_timestamp()
WHERE id = sqlc.arg(id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  AND status = 'draft' AND deleted_at IS NULL AND source_kind = 'pdf'
  AND html_source_json IS NULL
  AND updated_at = sqlc.arg(expected_updated_at)::timestamptz
RETURNING *;

-- name: MarkDocumentHTMLReviewed :one
-- The reviewer UUID is derived from the authenticated server actor. Retain
-- its live member/credential guard and document lock through audit and commit.
-- A review belongs to this exact PDF digest and observation, never a boolean.
UPDATE documents d
SET html_reviewed_pdf_sha256 = sqlc.arg(expected_pdf_sha256)::bytea,
    html_reviewed_by = sqlc.arg(reviewed_by)::uuid,
    html_reviewed_at = clock_timestamp(),
    html_reviewed_materialization_id = d.html_current_materialization_id,
    updated_at = clock_timestamp()
WHERE d.id = sqlc.arg(id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
  AND d.status = 'draft' AND d.deleted_at IS NULL AND d.source_kind = 'pdf'
  AND d.html_source_json IS NOT NULL
  AND d.pdf_sha256 = sqlc.arg(expected_pdf_sha256)::bytea
  AND d.updated_at = sqlc.arg(expected_updated_at)::timestamptz
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = sqlc.arg(reviewed_by)::uuid
      AND u.org_id = d.org_id
      AND (u.role = 'owner' OR (u.role = 'sender' AND u.id = d.sender_id)))
RETURNING d.*;

-- name: SetDocumentDefaultLocale :one
-- The sender's document-level default signing language. Draft-only: once sent,
-- recipients are locked, so the default can no longer change.
UPDATE documents
SET default_locale = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL
RETURNING *;

-- name: SetDocumentStatus :one
-- The generic state helper must never allocate a durable send/finalization
-- lifecycle state. Those transitions own immutable Article 13, retention, and
-- completion commitments and must use their dedicated guarded queries.
UPDATE documents
SET status = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2
  AND (
    ($3 = 'in_progress' AND documents.status = 'sent')
    OR ($3 = 'expired' AND documents.status IN ('sent', 'in_progress'))
  )
RETURNING *;

-- name: SetDocumentRequiresSignature :one
-- Draft-only toggle between signature-required and acknowledgement (view/accept)
-- mode. Locked once sent so recipients can't have the rules change under them.
UPDATE documents
SET requires_signature = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL
RETURNING *;

-- name: DeclineDocumentIfActive :one
-- Guarded decline transition: only an active (sent/in_progress) document can
-- move to declined. A completed/voided/declined/expired doc returns no row,
-- so a recipient with a still-live magic link cannot flip a terminal contract
-- to declined.
UPDATE documents
SET status = 'declined',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('sent','in_progress')
RETURNING *;

-- name: VoidDocumentIfActive :one
-- Guarded void transition: only an active sent/in-progress ceremony can be
-- voided. Draft, paused, and every terminal state return no row. This closes the Void race
-- where a plain GetDocument + unguarded status write could overwrite a doc
-- that finalize had just flipped to 'completed' (finalize holds only the
-- advisory lock, not a row lock) back to 'voided'. Mirrors
-- DeclineDocumentIfActive.
UPDATE documents
SET status = 'voided',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('sent', 'in_progress')
RETURNING *;

-- name: RequestChangesOnDocument :one
-- Guarded: an active (sent/in_progress) document pauses for changes. Already
-- paused (changes_requested) is allowed too so a signer can mark several spans.
UPDATE documents
SET status = 'changes_requested',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('sent','in_progress','changes_requested')
RETURNING *;

-- name: ExpireDocumentIfActive :one
-- Atomic expiration transition. The worker first discovers candidates with
-- GetExpirableDocuments, then uses this guarded write inside a transaction with
-- token invalidation + reminder cancellation. If signing/finalization wins the
-- race and makes the document terminal, this returns no row and the worker must
-- perform no expiration side effects.
UPDATE documents
SET status = 'expired',
    updated_at = now()
WHERE id = $1
  AND org_id = $2
  AND expires_at IS NOT NULL
  AND expires_at <= clock_timestamp()
  AND status IN ('sent','in_progress')
RETURNING *;

-- name: ApplyBlocksForChange :one
-- Apply an auto-approved inline change to a paused document's blocks. Scoped to
-- changes_requested so it only runs during the negotiation window.
UPDATE documents
SET blocks_json = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'changes_requested'
RETURNING *;

-- name: ReopenDocumentToDraft :one
-- The sender revises after a change request: a paused document returns to draft
-- so it can be edited and re-sent. article13_notice_epoch_at deliberately
-- survives: the next sealing completion must allocate a strictly newer epoch.
UPDATE documents
SET status = 'draft',
    sent_at = NULL,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'changes_requested'
RETURNING *;

-- name: GetStrandedDocuments :many
-- Documents ready for terminal artifact completion but stranded in_progress,
-- plus finalizing documents whose exact staged artifacts need retention or a
-- terminal SQL retry after a crash.
-- SQL deliberately selects a broad bounded candidate set. Required roles for
-- block documents depend on the frozen conditional tree and custom roles, so
-- reimplementing that expression language in JSONPath would diverge from the
-- signer/PDF projection. The signing engine is the sole readiness authority
-- and re-checks the exact frozen role set before any terminal write.
-- Keep crash-resume work ahead of not-yet-claimed rows, but select the oldest
-- candidate in each class first. Newer failures must not continually displace
-- a contract that has already waited longer; id makes equal timestamps stable.
SELECT d.* FROM documents d
WHERE d.status IN ('in_progress','finalizing')
  AND d.final_pdf_key IS NULL
  AND d.deleted_at IS NULL
  -- Envelope children share their root's ceremony, terminal artifact, and
  -- finalization intent. They must never be retried as standalone documents.
  AND d.parent_envelope_id IS NULL
  AND (
    d.status = 'finalizing'
    OR
    (
      d.requires_signature = false
      AND NOT EXISTS (
        SELECT 1 FROM recipients r
        WHERE r.document_id = d.id
          AND r.role <> 'cc'
          AND r.status NOT IN ('accepted','declined')
      )
    )
    OR (
      d.requires_signature = true
      AND EXISTS (
        SELECT 1 FROM recipients signed
        WHERE signed.document_id = d.id
          AND signed.status = 'signed'
      )
    )
  )
ORDER BY (d.status = 'finalizing') DESC, d.updated_at ASC, d.id ASC
LIMIT $1;

-- name: DeleteDraftDocument :exec
-- Soft-delete: flip deleted_at so the row stays available for GDPR
-- Art. 15 / Art. 30 evidence retrieval during the 90-day grace
-- window. A separate worker prunes anything past that boundary.
UPDATE documents
SET deleted_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL;

-- name: SetDocumentLawfulBasis :exec
UPDATE documents
SET lawful_basis = $3
WHERE id = $1 AND org_id = $2;

-- name: ClaimSoftDeletedDocumentsForPurge :many
-- Lease a bounded batch before object-store cleanup. updated_at doubles as a
-- recoverable lease timestamp for already-deleted drafts: peers skip a claim
-- for 15 minutes, while a crashed worker leaves it eligible for a later retry.
-- The row remains intact until its document-owned source object is confirmed
-- deleted, preserving the key needed to retry storage cleanup.
WITH candidates AS (
  SELECT documents.id
  FROM documents
  WHERE documents.deleted_at IS NOT NULL
    AND documents.deleted_at < sqlc.arg(cutoff)
    AND documents.status = 'draft'
    AND documents.updated_at <= now() - interval '15 minutes'
    AND NOT EXISTS (SELECT 1 FROM data_subject_requests r
        WHERE r.org_id = documents.org_id
          AND (r.document_id = documents.id OR r.document_id IS NULL)
          AND r.status IN ('open','in_progress'))
  ORDER BY documents.deleted_at
  FOR UPDATE SKIP LOCKED
  LIMIT sqlc.arg(batch_limit)
)
UPDATE documents d
SET updated_at = now()
FROM candidates
WHERE d.id = candidates.id
RETURNING d.*;

-- name: LockClaimedSoftDeletedDocumentForPurge :one
-- Hold this exact leased parent before privacy fences and object-store I/O.
-- Another worker, privacy transition, or stale lease must not authorize cleanup.
SELECT * FROM documents
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id)
  AND deleted_at IS NOT NULL AND deleted_at < sqlc.arg(cutoff)
  AND status = 'draft' AND updated_at = sqlc.arg(updated_at)
FOR UPDATE SKIP LOCKED;

-- name: HasPendingDocumentPrivacyRequests :one
-- Caller holds document FOR UPDATE and the organization privacy fence, OR
-- the actual M102 linked-document shared fence plus that organization fence.
-- A fresh statement snapshot observes both linked and organization-wide review.
SELECT EXISTS(SELECT 1 FROM data_subject_requests
WHERE org_id = sqlc.arg(org_id)::uuid
  AND (document_id = sqlc.arg(document_id)::uuid OR document_id IS NULL)
  AND status IN ('open','in_progress')) AS pending;

-- name: HasOtherDocumentSourceReferences :one
-- Include deleted drafts and foreign organizations: object ownership must never
-- be inferred solely from the deleting row or the caller's tenant visibility.
SELECT EXISTS(
  SELECT 1 FROM documents d WHERE d.id <> sqlc.arg(document_id)
    AND sqlc.arg(object_key)::text IN (d.pdf_storage_key,d.rendered_pdf_key,d.final_pdf_key,d.audit_cert_key,d.audit_payload_key,d.audit_signature_key)
  UNION ALL
  SELECT 1 FROM document_amendments_v1 a
    CROSS JOIN LATERAL jsonb_array_elements(convert_from(a.file_set,'UTF8')::jsonb->'files') f
    WHERE f->>'key'=sqlc.arg(object_key)::text
  UNION ALL
  SELECT 1 FROM templates t WHERE t.pdf_storage_key = sqlc.arg(object_key)::text
  UNION ALL
  SELECT 1 FROM document_finalization_intents i
    WHERE sqlc.arg(object_key)::text IN (i.final_pdf_key,i.audit_cert_key,i.audit_payload_key,i.audit_signature_key)
  UNION ALL
  SELECT 1 FROM signatures s WHERE s.image_storage_key = sqlc.arg(object_key)::text
  UNION ALL
  SELECT 1 FROM document_package_capture_members_v1 c WHERE c.pdf_key = sqlc.arg(object_key)::text
  UNION ALL
  SELECT 1 FROM document_attachment_drafts_v1 a WHERE a.pdf_key = sqlc.arg(object_key)::text
  UNION ALL
  SELECT 1 FROM html_document_materializations m WHERE m.pdf_key = sqlc.arg(object_key)::text
  UNION ALL
  SELECT 1 FROM html_document_materialization_snapshots h
    WHERE sqlc.arg(object_key)::text IN (h.pdf_key, h.rendered_pdf_key)
) AS shared;

-- name: HasRetainedDraftSigningEvidence :one
-- Caller holds the parent lock. An anomalous draft can still carry signing
-- evidence or an unfinished sealing intent; retain both the row and its source
-- before any draft mutation. Historical HTML rows do not forbid reversible
-- editing; destructive purge adds its independent retained-history fence.
SELECT EXISTS(
  SELECT 1 FROM documents d
    WHERE d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
      AND (d.final_pdf_key IS NOT NULL OR d.final_pdf_sha IS NOT NULL OR d.final_pdf_version_id IS NOT NULL
        OR d.audit_cert_key IS NOT NULL OR d.audit_cert_sha256 IS NOT NULL OR d.audit_cert_version_id IS NOT NULL
        OR d.audit_payload_key IS NOT NULL OR d.audit_payload_sha256 IS NOT NULL OR d.audit_payload_version_id IS NOT NULL
        OR d.audit_signature_key IS NOT NULL OR d.audit_signature_sha256 IS NOT NULL OR d.audit_signature_version_id IS NOT NULL)
  UNION ALL
  SELECT 1 FROM document_finalization_intents WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM send_sealing_intents WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM document_package_responses_v1 WHERE document_id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  UNION ALL
  SELECT 1 FROM document_ordinary_finalization_preparations_v1 WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND (retain_until>=clock_timestamp() OR bodies_retired_at IS NULL)
  UNION ALL
  SELECT 1 FROM document_participant_reports_v1 WHERE document_id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  UNION ALL
  SELECT 1 FROM document_participant_report_legacy_intents_v1 WHERE document_id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  UNION ALL
  SELECT 1 FROM signatures WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM recipients WHERE document_id = sqlc.arg(document_id)::uuid
    AND (status IN ('signed','accepted') OR signed_at IS NOT NULL)
  UNION ALL
  SELECT 1 FROM document_fields WHERE document_id = sqlc.arg(document_id)::uuid
    AND (value IS NOT NULL OR completed_at IS NOT NULL)
) AS retained;

-- name: HasRetainedDraftEvidenceForPurge :one
-- Caller holds the parent lock. An anomalous draft can still carry signing
-- evidence or an unfinished sealing intent; retain both the row and its source
-- before any irreversible object operation. Match Revise's captured-data gate.
SELECT EXISTS(
  SELECT 1 FROM documents d
    WHERE d.id = sqlc.arg(document_id)::uuid AND d.org_id = sqlc.arg(org_id)::uuid
      AND (d.final_pdf_key IS NOT NULL OR d.final_pdf_sha IS NOT NULL OR d.final_pdf_version_id IS NOT NULL
        OR d.audit_cert_key IS NOT NULL OR d.audit_cert_sha256 IS NOT NULL OR d.audit_cert_version_id IS NOT NULL
        OR d.audit_payload_key IS NOT NULL OR d.audit_payload_sha256 IS NOT NULL OR d.audit_payload_version_id IS NOT NULL
        OR d.audit_signature_key IS NOT NULL OR d.audit_signature_sha256 IS NOT NULL OR d.audit_signature_version_id IS NOT NULL)
  UNION ALL
  SELECT 1 FROM document_amendments_v1 a WHERE a.org_id=sqlc.arg(org_id)::uuid
    AND (a.original_document_id=sqlc.arg(document_id)::uuid OR a.document_id=sqlc.arg(document_id)::uuid
      OR EXISTS(SELECT 1 FROM jsonb_array_elements(convert_from(a.file_set,'UTF8')::jsonb->'files') f WHERE (f->>'document_id')::uuid=sqlc.arg(document_id)::uuid))
  UNION ALL
  SELECT 1 FROM document_finalization_intents WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM send_sealing_intents WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM document_package_send_attempts_v1 WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM document_package_responses_v1 WHERE document_id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  UNION ALL
  SELECT 1 FROM document_ordinary_finalization_preparations_v1 WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid AND (retain_until>=clock_timestamp() OR bodies_retired_at IS NULL)
  UNION ALL
  SELECT 1 FROM document_participant_reports_v1 WHERE document_id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  UNION ALL
  SELECT 1 FROM document_participant_report_legacy_intents_v1 WHERE document_id = sqlc.arg(document_id)::uuid AND org_id = sqlc.arg(org_id)::uuid
  UNION ALL
  SELECT 1 FROM document_packages_v1 WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM document_package_capture_members_v1 WHERE member_document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM document_attachment_drafts_v1 WHERE member_document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM html_document_materializations WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM html_document_materialization_snapshots WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM signatures WHERE document_id = sqlc.arg(document_id)::uuid
  UNION ALL
  SELECT 1 FROM recipients WHERE document_id = sqlc.arg(document_id)::uuid
    AND (status IN ('signed','accepted') OR signed_at IS NOT NULL)
  UNION ALL
  SELECT 1 FROM document_fields WHERE document_id = sqlc.arg(document_id)::uuid
    AND (value IS NOT NULL OR completed_at IS NOT NULL)
) AS retained;

-- name: DeleteClaimedSoftDeletedDocument :execrows
-- Hard-delete only the exact draft lease the worker just cleaned. If any
-- concurrent state change touched updated_at, the CAS fails and no legal row is
-- removed. events.document_id uses ON DELETE SET NULL, preserving the org chain.
DELETE FROM documents d
WHERE d.id = $1
  AND d.org_id = $2
  AND d.deleted_at IS NOT NULL
  AND d.deleted_at < $3
  AND d.status = 'draft'
  AND d.updated_at = $4
  AND NOT EXISTS (SELECT 1 FROM data_subject_requests r
      WHERE r.org_id = d.org_id AND (r.document_id = d.id OR r.document_id IS NULL)
        AND r.status IN ('open','in_progress'));

-- name: SearchDocumentsByName :many
SELECT * FROM documents
WHERE org_id = $1 AND deleted_at IS NULL AND name ILIKE '%' || $2 || '%'
ORDER BY updated_at DESC
LIMIT $3;

-- name: SearchDocumentsByNameForMCP :many
-- The same bounded projection as MCP lists; no full JSON row materialization.
SELECT d.id, d.org_id, d.template_id, d.name,
    d.status, d.routing_mode, d.source_kind, d.blocks_json,
    d.variables_json, d.rendered_pdf_key, d.rendered_pdf_sha, d.pdf_storage_key,
    d.pdf_sha256, d.final_pdf_key, d.final_pdf_sha, d.audit_cert_key,
    d.expires_at, d.sent_at, d.completed_at, d.sender_id,
    d.metadata, d.created_at, d.updated_at, d.parent_envelope_id,
    d.envelope_position, d.is_envelope, d.metadata_redaction_report, d.routing_tier,
    d.negotiation_enabled, d.bilingual_target_lang, d.lawful_basis, d.deleted_at,
    d.default_locale, d.requires_signature, d.audit_payload_key, d.audit_payload_sha256,
    d.audit_signature_key, d.audit_signature_sha256, d.pdf_storage_version_id, d.rendered_pdf_version_id,
    d.final_pdf_version_id, d.audit_cert_sha256, d.audit_cert_version_id, d.audit_payload_version_id,
    d.audit_signature_version_id, d.evidence_version_pins_required, d.completion_effective_at, d.completion_effective_at_bound,
    d.finalization_retain_until, d.article13_notice_epoch_at, d.article13_notice_schema, d.article13_notice_epoch_v61_committed,
    NULL::jsonb AS html_source_json, d.html_reviewed_pdf_sha256, d.html_reviewed_by, d.html_reviewed_at,
    d.html_current_materialization_id, NULL::jsonb AS html_current_source_json, d.html_current_page_count, d.html_current_materialization_sequence,
    d.html_reviewed_materialization_id, d.html_effective_source_commitment,
    d.signature_fit_reserved_bytes, d.fits_index_required, d.fits_index_preparation_id, d.fits_index_storage_key,
    d.fits_index_version_id, d.fits_index_sha256, d.fits_index_bytes, d.signature_fit_original_payload_bytes,
    d.signature_fit_original_authority_bytes, d.signature_fit_original_authority_count, d.signing_admission_policy, d.signing_admission_active_id,
    d.signing_admission_sealed_id, d.signing_admission_count, d.signing_admission_static_bytes, d.signing_admission_ordinary_bytes,
    d.signing_admission_plan_bytes, d.signature_fit_request_binding_bytes, d.signature_fit_request_binding_count, d.participant_report_schema
FROM documents d
WHERE d.org_id = $1 AND d.deleted_at IS NULL AND d.name ILIKE '%' || $2 || '%'
ORDER BY d.updated_at DESC
LIMIT $3;

-- name: GetExpirableDocuments :many
SELECT * FROM documents
WHERE expires_at IS NOT NULL
  AND deleted_at IS NULL
  AND expires_at <= now()
  AND status IN ('sent','in_progress')
LIMIT $1;
-- name: FreezeDocumentVariables :one
-- Source-neutral values are committed only inside authorized draft creation
-- or send, after the current draft revision has been checked.
UPDATE documents
SET variables_json = $3, updated_at = clock_timestamp()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL
  AND updated_at = sqlc.arg(expected_updated_at)
RETURNING *;

-- Native fixed HTML creation writer owns this explicit fresh INSERT. The
-- target is the physical session accounting scope, never an existing-row hint.
-- Original variables are known literal {} before the admitted values write.
-- name: CreateFreshHTMLPDFDocumentV1 :one
INSERT INTO documents (id,org_id,template_id,name,source_kind,variables_json,
 pdf_storage_key,pdf_sha256,pdf_storage_version_id,evidence_version_pins_required,sender_id,expires_at)
VALUES (sqlc.arg(id),sqlc.arg(org_id),sqlc.arg(template_id),sqlc.arg(name),
 'pdf','{}'::jsonb,sqlc.arg(pdf_storage_key),sqlc.arg(pdf_sha256),sqlc.arg(pdf_storage_version_id),
 sqlc.arg(evidence_version_pins_required),sqlc.arg(sender_id),sqlc.arg(expires_at))
RETURNING *;
