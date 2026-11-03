// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package documentfolders

import (
	"context"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This dedicated projection deliberately reuses the existing REST metadata
// shape. It never selects either embedded HTML master or changes generated
// document models, signing source, timestamps or evidence.
const documentProjection = `d.id,d.org_id,d.template_id,d.name,d.status,d.routing_mode,
 d.source_kind,d.requires_signature,d.blocks_json,d.variables_json,
 d.pdf_storage_key,d.pdf_sha256,d.final_pdf_key,d.final_pdf_sha,d.audit_cert_key,
 d.expires_at,d.sent_at,d.completed_at,d.sender_id,d.metadata,d.default_locale,
 d.created_at,d.updated_at,d.parent_envelope_id,d.envelope_position,d.is_envelope,
 (d.html_source_json IS NOT NULL),
 (d.html_source_json IS NOT NULL AND (
  d.html_reviewed_by IS NULL OR d.html_reviewed_at IS NULL
  OR d.pdf_sha256 IS NULL OR octet_length(d.pdf_sha256) <> 32
  OR d.html_reviewed_pdf_sha256 IS DISTINCT FROM d.pdf_sha256
  OR (d.html_current_materialization_id IS NOT NULL
   AND d.html_reviewed_materialization_id IS DISTINCT FROM d.html_current_materialization_id))),
 d.html_current_materialization_sequence,d.html_effective_source_commitment,m.folder_id`

// Both pagination and count use this exact predicate. An organization is
// always explicit, including every sidecar join; an unknown folder must first
// pass the same organization's scalar identity lookup.
const documentScope = `FROM documents d
 LEFT JOIN document_folder_memberships m ON m.document_id=d.id AND m.org_id=d.org_id
 WHERE d.org_id=$1 AND d.deleted_at IS NULL
 AND ($2::text[] IS NULL OR d.status=ANY($2::text[]))
 AND ($3::text='all' OR ($3::text='unfiled' AND m.document_id IS NULL)
  OR ($3::text='folder' AND m.folder_id=$4::uuid))`

func scanDocument(row pgx.Row) (Document, error) {
	var out Document
	d := &out.Metadata
	var folder pgtype.UUID
	err := row.Scan(&d.ID, &d.OrgID, &d.TemplateID, &d.Name, &d.Status, &d.RoutingMode,
		&d.SourceKind, &d.RequiresSignature, &d.BlocksJson, &d.VariablesJson,
		&d.PdfStorageKey, &d.PdfSha256, &d.FinalPdfKey, &d.FinalPdfSha, &d.AuditCertKey,
		&d.ExpiresAt, &d.SentAt, &d.CompletedAt, &d.SenderID, &d.Metadata, &d.DefaultLocale,
		&d.CreatedAt, &d.UpdatedAt, &d.ParentEnvelopeID, &d.EnvelopePosition, &d.IsEnvelope,
		&d.HasHtmlSource, &d.HtmlReviewRequired, &d.HtmlCurrentMaterializationSequence,
		&d.HtmlEffectiveSourceCommitment, &folder)
	if folder.Valid {
		id := uuid.UUID(folder.Bytes)
		out.FolderID = &id
	}
	return out, err
}

func scanFolder(row pgx.Row) (Folder, error) {
	var folder Folder
	err := row.Scan(&folder.ID, &folder.Name, &folder.DocumentCount, &folder.CreatedAt, &folder.UpdatedAt)
	return folder, err
}

const folderColumns = `f.id,f.name,
 (SELECT count(*) FROM document_folder_memberships m JOIN documents d ON d.id=m.document_id AND d.org_id=m.org_id
  WHERE m.folder_id=f.id AND m.org_id=f.org_id AND d.deleted_at IS NULL),f.created_at,f.updated_at`

func getFolder(ctx context.Context, db generated.DBTX, org, id any) (Folder, error) {
	return scanFolder(db.QueryRow(ctx, `SELECT `+folderColumns+` FROM document_folders f WHERE f.org_id=$1 AND f.id=$2`, org, id))
}
