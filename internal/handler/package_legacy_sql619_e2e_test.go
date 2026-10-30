//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

// These SQL-only historical fixture statements retain the original production
// query predicates. Only argument spelling and RETURNING projections differ,
// avoiding modern Document/SendSealingIntent decoding at M104/M105/M106.
// They grant no modern application authority or provider/e-signature evidence.

const legacyPackageIntent619 = `INSERT INTO send_sealing_intents(document_id,org_id,actor_user_id,actor_email,actor_ip,via,tool,
 article13_notice_epoch_at,retain_until,package_send_attempt_id)
SELECT a.document_id,a.org_id,a.actor_user_id,u.email,$1::text,$2::text,$3::text,
 a.article13_notice_epoch_at,a.retain_until,a.attempt_id
FROM document_package_send_attempts_v1 a JOIN users u ON u.id=a.actor_user_id AND u.org_id=a.org_id
WHERE a.attempt_id=$4::uuid AND a.org_id=$5::uuid AND a.document_id=$6::uuid
 AND a.terminal_outcome IS NULL
RETURNING document_id;`

const legacyPackageRetentionStart619 = `UPDATE send_sealing_intents i SET retention_started_at=COALESCE(i.retention_started_at,clock_timestamp()),updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=$1::uuid AND a.org_id=$2::uuid AND a.document_id=$3::uuid
 AND a.manifest_sha256=$4::bytea AND a.legal_commitment_sha256=$5::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
 AND i.retention_completed_at IS NULL
RETURNING i.document_id;`

const legacyPackageRetentionComplete619 = `UPDATE send_sealing_intents i SET retention_completed_at=COALESCE(i.retention_completed_at,clock_timestamp()),
 attempts=i.attempts+1,last_error=NULL,updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=$1::uuid AND a.org_id=$2::uuid AND a.document_id=$3::uuid
 AND a.manifest_sha256=$4::bytea AND a.legal_commitment_sha256=$5::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
 AND i.retention_started_at IS NOT NULL
RETURNING i.document_id;`

const legacyPackageRetentionSync619 = `UPDATE document_package_send_attempts_v1 a SET retention_started_at=i.retention_started_at,retention_completed_at=i.retention_completed_at
FROM send_sealing_intents i
WHERE a.attempt_id=$1::uuid AND a.org_id=$2::uuid AND a.document_id=$3::uuid
 AND a.manifest_sha256=$4::bytea AND a.legal_commitment_sha256=$5::bytea
 AND a.terminal_outcome IS NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
RETURNING a.attempt_id;`

const legacyPackagePin619 = `UPDATE documents
SET pdf_storage_version_id = CASE
        WHEN pdf_storage_key IS NULL THEN NULL
        ELSE COALESCE(pdf_storage_version_id, $3::text)
    END,
    rendered_pdf_version_id = CASE
        WHEN rendered_pdf_key IS NULL THEN NULL
        ELSE COALESCE(rendered_pdf_version_id, $4::text)
    END,
    evidence_version_pins_required = TRUE,
    updated_at = now()
WHERE id = $1
  AND org_id = $2
  AND status IN ('sealing','sent','in_progress','finalizing')
  AND deleted_at IS NULL
  AND (
    (pdf_storage_key IS NULL AND $3::text IS NULL)
    OR (
      pdf_storage_key IS NOT NULL
      AND NULLIF($3::text, '') IS NOT NULL
      AND (pdf_storage_version_id IS NULL OR pdf_storage_version_id = $3::text)
    )
  )
  AND (
    (rendered_pdf_key IS NULL AND $4::text IS NULL)
    OR (
      rendered_pdf_key IS NOT NULL
      AND NULLIF($4::text, '') IS NOT NULL
      AND (rendered_pdf_version_id IS NULL OR rendered_pdf_version_id = $4::text)
    )
  )
RETURNING id;`

const legacyPackageComplete619 = `UPDATE documents d SET status='sent',sent_at=a.article13_notice_epoch_at,article13_notice_epoch_at=a.article13_notice_epoch_at,
 article13_notice_schema='hash-a13-2026-08-31',article13_notice_epoch_v61_committed=TRUE,updated_at=clock_timestamp()
FROM document_package_send_attempts_v1 a JOIN send_sealing_intents i
 ON i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
WHERE a.attempt_id=$1::uuid AND a.org_id=$2::uuid AND a.document_id=$3::uuid
 AND a.manifest_sha256=$4::bytea AND a.legal_commitment_sha256=$5::bytea
 AND a.terminal_outcome IS NULL AND i.retention_started_at IS NOT NULL AND i.retention_completed_at IS NOT NULL
 AND a.retention_started_at=i.retention_started_at AND a.retention_completed_at=i.retention_completed_at
 AND d.id=a.document_id AND d.org_id=a.org_id AND d.status='sealing' AND d.deleted_at IS NULL AND d.evidence_version_pins_required
 AND (d.article13_notice_epoch_at IS NULL OR a.article13_notice_epoch_at>d.article13_notice_epoch_at)
RETURNING d.id,d.sent_at,d.article13_notice_schema;`
