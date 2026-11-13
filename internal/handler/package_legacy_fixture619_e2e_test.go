//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

// These journeys qualify historical SQL protocols, not modern Send or provider
// effects. Draft/capture/branding have genuine current native producers. Only
// after a real guarded Down do the old SQL attempt, intent and sealing commit
// together. M103 forbids committing an active draft+intent pair; M111 refuses
// downgrading a sealing root. Neither guard is disabled or worked around.
func packageLegacyAttempt619(t *testing.T, q *ownedPublicReadFixtureV1, version int64) pdfadmission.HTMLSendPackageIntentMetadataV1 {
	t.Helper()
	root := packageImported220(t, q, "Historical SQL protocol source")
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	var c pdfadmission.HTMLSendPackageCaptureMetadataV1
	err := packageCaptureRun234(t, q, root, p, nil, func(ctx context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
		var err error
		c, err = packageCaptureAppend234(t, ctx, w, prior)
		if err != nil {
			return err
		}
		_, err = w.FreezeBrandingV1(ctx)
		return err
	})
	if err != nil {
		t.Fatal("native historical capture/branding preparation", err)
	}
	packageCaptureReadback234(t, q, root, p, c)
	// Branding's native producer changes only its snapshot, not the document
	// clock. Verify the committed current row/generation rather than assigning
	// a replacement timestamp to the capture or restoring any source row.
	var updated pgtype.Timestamptz
	var generation int64
	var status string
	var branded bool
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT d.updated_at,d.status,p.draft_generation,hash_document_has_valid_frozen_branding(d.id)
 FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE d.id=$1 AND d.org_id=$2 AND p.id=$3`, c.DocumentID, c.OrgID, c.PackageID).Scan(&updated, &status, &generation, &branded); err != nil || !updated.Valid || !updated.Time.Equal(c.RootUpdatedAt) || status != "draft" || generation != c.DraftGeneration || !branded {
		t.Fatal("native committed capture/branding lost its exact draft clock or generation", err)
	}
	packageLegacySchema619(t, q, version)
	requests := q.storagePeer.requests.Load()
	tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	id := uuid.New()
	a, err := legacyPackageCreate619(q.f.ctx, tx, id, c)
	if err != nil || a == nil || a.AttemptID != id || a.OrgID != c.OrgID || a.DocumentID != c.DocumentID || a.PackageID != c.PackageID || a.CaptureRevision != c.Revision || a.PreviousRevision != c.PreviousRevision || a.CapturedDraftGeneration != c.DraftGeneration || !a.CapturedRootUpdatedAt.Time.Equal(c.RootUpdatedAt) || a.ManifestBytes != c.ManifestBytes || a.MemberCount != c.MemberCount || a.PdfBytes != c.PDFBytes || a.PdfPages != c.PDFPages || !bytes.Equal(a.ManifestSha256, c.CanonicalSHA256[:]) || !bytes.Equal(a.LegalCommitmentSha256, c.CommitmentSHA256[:]) || a.ActorUserID != c.CreatedBy || !a.CreatedAt.Valid || !a.Article13NoticeEpochAt.Valid || !a.RetainUntil.Valid || !a.RetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(a.Article13NoticeEpochAt.Time, article13.RetentionYearsV1)) {
		t.Fatal("historical SQL attempt changed native capture commitments", err)
	}
	m := pdfadmission.HTMLSendPackageIntentMetadataV1{AttemptID: id, Capture: c, CreatedAt: a.CreatedAt.Time.UTC(), Article13NoticeEpochAt: a.Article13NoticeEpochAt.Time.UTC(), RetainUntil: a.RetainUntil.Time.UTC()}
	if err := legacyPackageExec619(q.f.ctx, tx, legacyPackageIntent619, "127.0.0.1", "synthetic-owned-test", "exact-package-attempt", id, c.OrgID, c.DocumentID); err != nil {
		t.Fatal("historical exact intent", err)
	}
	if err := legacyPackageExec619(q.f.ctx, tx, `UPDATE documents d SET status='sealing',updated_at=now()
 FROM send_sealing_intents i JOIN document_package_send_attempts_v1 a ON a.attempt_id=i.package_send_attempt_id AND a.org_id=i.org_id AND a.document_id=i.document_id
 WHERE d.id=$3 AND d.org_id=$2 AND d.status='draft' AND d.deleted_at IS NULL
 AND a.attempt_id=$1 AND a.org_id=d.org_id AND a.document_id=d.id AND a.terminal_outcome IS NULL
 AND a.manifest_sha256=$4 AND a.legal_commitment_sha256=$5
 AND i.retention_started_at IS NULL AND i.retention_completed_at IS NULL RETURNING d.id`, legacyPackageArgs619(m)...); err != nil {
		t.Fatal("historical exact sealing", err)
	}
	if _, err := tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(q.f.ctx); err != nil {
		t.Fatal(err)
	}
	if q.storagePeer.requests.Load() != requests {
		t.Fatal("historical SQL birth performed provider IO")
	}
	return m
}

func packageLegacySchema619(t *testing.T, q *ownedPublicReadFixtureV1, version int64) {
	t.Helper()
	if version < 104 || version > 106 {
		t.Fatal("unsupported explicit historical package boundary")
	}
	assertCurrentHandlerMigrationHistoryE2E(t, q.f.ctx, q.f.pool)
	cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()
	if err := mdb.RunMigrationsDownToContext(q.f.ctx, db, version); err != nil {
		t.Fatal("guarded downgrade before historical SQL birth", err)
	}
	if actual, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || actual != version {
		t.Fatal("historical package schema boundary differs", actual, err)
	}
}

func legacyPackageArgs619(m pdfadmission.HTMLSendPackageIntentMetadataV1) []any {
	return []any{m.AttemptID, m.Capture.OrgID, m.Capture.DocumentID, m.Capture.CanonicalSHA256[:], m.Capture.CommitmentSHA256[:]}
}

func legacyPackageExec619(ctx context.Context, tx pgx.Tx, sql string, args ...any) error {
	result, err := tx.Exec(ctx, sql, args...)
	if err == nil && result.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return err
}

type legacyPackageRoot619 struct {
	id, org       uuid.UUID
	pdf, rendered pgtype.Text
}

func legacyPackageLock619(ctx context.Context, tx pgx.Tx, m pdfadmission.HTMLSendPackageIntentMetadataV1) (legacyPackageRoot619, error) {
	var root legacyPackageRoot619
	err := tx.QueryRow(ctx, `SELECT id,org_id,pdf_storage_version_id,rendered_pdf_version_id FROM documents
 WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL AND status='sealing' AND evidence_version_pins_required FOR UPDATE`, m.Capture.DocumentID, m.Capture.OrgID).Scan(&root.id, &root.org, &root.pdf, &root.rendered)
	return root, err
}

func packageLegacyAggregateStart619(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) {
	t.Helper()
	tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	if _, err := legacyPackageLock619(q.f.ctx, tx, m); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{legacyPackageRetentionStart619, legacyPackageRetentionSync619} {
		if err := legacyPackageExec619(q.f.ctx, tx, sql, legacyPackageArgs619(m)...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(q.f.ctx); err != nil {
		t.Fatal(err)
	}
}

func packageLegacyCompletionStage619(t *testing.T, q *ownedPublicReadFixtureV1, tx pgx.Tx, m pdfadmission.HTMLSendPackageIntentMetadataV1, members, narrowAudit bool) error {
	t.Helper()
	ctx := q.f.ctx
	args := legacyPackageArgs619(m)
	root, err := legacyPackageLock619(ctx, tx, m)
	if err != nil {
		return err
	}
	for _, sql := range []string{legacyPackageRetentionStart619, legacyPackageRetentionSync619} {
		if err := legacyPackageExec619(ctx, tx, sql, args...); err != nil {
			return err
		}
	}
	if members {
		if err := packageMemberRetentionSQLReceipts240(ctx, generated.New(tx), m); err != nil {
			return err
		}
	}
	for _, sql := range []string{legacyPackageRetentionComplete619, legacyPackageRetentionSync619} {
		if err := legacyPackageExec619(ctx, tx, sql, args...); err != nil {
			return err
		}
	}
	if err := legacyPackageExec619(ctx, tx, legacyPackagePin619, root.id, root.org, root.pdf, root.rendered); err != nil {
		return err
	}
	var id uuid.UUID
	var sent pgtype.Timestamptz
	var schema string
	if err := tx.QueryRow(ctx, legacyPackageComplete619, args...).Scan(&id, &sent, &schema); err != nil {
		return err
	}
	if id != root.id || !sent.Valid || !sent.Time.Equal(m.Article13NoticeEpochAt) {
		return errors.New("historical completion changed exact attempt epoch")
	}
	epoch, err := article13.CanonicalSentAt(sent.Time)
	if err != nil {
		return err
	}
	payload := map[string]any{article13.AuditRequiredNoticeSchemaKey: schema, article13.AuditRequiredNoticeSentAtKey: epoch}
	if members {
		payload["recipient_count"] = 0
	}
	if narrowAudit {
		payload = packageCompletionPayload241(m, payload)
	}
	_, err = q.f.s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: root.org, DocumentID: &root.id, ActorUserID: &q.f.user.ID, Kind: audit.KindDocumentSent, Payload: payload})
	return err
}

func packageLegacyComplete619(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) error {
	t.Helper()
	tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	if err := packageLegacyCompletionStage619(t, q, tx, m, true, true); err != nil {
		return err
	}
	if _, err := generated.New(tx).RecordDocumentPackageSendCompletionV1(q.f.ctx, packageCompletionRecordParams241(m)); err != nil {
		return err
	}
	if err := packageLegacyTerminal619(q.f.ctx, tx, m); err != nil {
		return err
	}
	if _, err := tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return err
	}
	return tx.Commit(q.f.ctx)
}

func packageLegacyWorkerBirth619(t *testing.T, q *ownedPublicReadFixtureV1, occupied bool) packageWorkerJob239 {
	t.Helper()
	if !occupied {
		root := packageImported220(t, q, "Empty recovery queue schema witness")
		_ = packageCreate223(t, q, root)
		packageWorkerDrained239(t, q)
		packageLegacySchema619(t, q, 104)
		return packageWorkerJob239{}
	}
	m := packageLegacyAttempt619(t, q, 104)
	packageWorkerDrained239(t, q)
	var created time.Time
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT created_at FROM document_package_send_attempts_v1 WHERE attempt_id=$1", m.AttemptID).Scan(&created); err != nil {
		t.Fatal(err)
	}
	return packageWorkerJob239{meta: m, created: created.UTC()}
}

// Frozen generated attempt SQL/row from 27ea46856e9ed9aaac3f8bc56a45b8c08c643102.
// M104/M105/M106 fixtures must not insert or select M128 incorporation columns.
// Native current capture/branding still happens before the real guarded Down;
// all historical scope, commitment, epoch, terminal and missing/foreign checks
// are retained, with no fabricated schema columns or response evidence.
const legacyPackageCreateAttemptSQL619 = `-- name: CreateDocumentPackageSendAttemptV1 :one
WITH candidate AS MATERIALIZED (
 SELECT c.package_id,c.revision,c.previous_revision,c.org_id,c.document_id,c.captured_root_updated_at,
 c.captured_draft_generation,octet_length(c.manifest)::integer AS manifest_bytes,
 c.manifest_sha256,c.legal_commitment_sha256,c.member_count,c.pdf_bytes,c.pdf_pages,c.created_by,
 GREATEST(statement_timestamp(),clock_timestamp(),COALESCE(d.article13_notice_epoch_at+interval '1 microsecond','-infinity'::timestamptz)) AS epoch
 FROM document_package_captures_v1 c JOIN documents d ON d.id=c.document_id AND d.org_id=c.org_id
 WHERE c.package_id=$2::uuid AND c.revision=$3::bigint
 AND c.org_id=$4::uuid AND c.document_id=$5::uuid
 AND c.captured_root_updated_at=$6::timestamptz
 AND c.captured_draft_generation=$7::bigint
 AND c.previous_revision=$8::bigint
 AND octet_length(c.manifest)=$9::integer
 AND c.manifest_sha256=$10::bytea
 AND c.legal_commitment_sha256=$11::bytea
 AND c.member_count=$12::smallint
 AND c.pdf_bytes=$13::bigint AND c.pdf_pages=$14::integer
 AND c.created_by=$15::uuid
)
INSERT INTO document_package_send_attempts_v1(attempt_id,org_id,document_id,package_id,capture_revision,previous_revision,
 manifest_bytes,member_count,pdf_bytes,pdf_pages,captured_root_updated_at,captured_draft_generation,
 manifest_sha256,legal_commitment_sha256,actor_user_id,article13_notice_epoch_at,retain_until)
SELECT $1::uuid,org_id,document_id,package_id,revision,previous_revision,manifest_bytes,member_count,pdf_bytes,pdf_pages,
 captured_root_updated_at,captured_draft_generation,manifest_sha256,legal_commitment_sha256,created_by,epoch,hash_evidence_retain_until(epoch,7)
FROM candidate RETURNING attempt_id, org_id, document_id, package_id, capture_revision, previous_revision, manifest_bytes, member_count, pdf_bytes, pdf_pages, captured_root_updated_at, captured_draft_generation, manifest_sha256, legal_commitment_sha256, actor_user_id, article13_notice_epoch_at, retain_until, retention_started_at, retention_completed_at, terminal_outcome, terminal_at, created_at
`

const legacyPackageInspectAttemptSQL619 = `-- name: InspectDocumentPackageSendAttemptV1 :one
SELECT a.attempt_id, a.org_id, a.document_id, a.package_id, a.capture_revision, a.previous_revision, a.manifest_bytes, a.member_count, a.pdf_bytes, a.pdf_pages, a.captured_root_updated_at, a.captured_draft_generation, a.manifest_sha256, a.legal_commitment_sha256, a.actor_user_id, a.article13_notice_epoch_at, a.retain_until, a.retention_started_at, a.retention_completed_at, a.terminal_outcome, a.terminal_at, a.created_at,(EXISTS(SELECT 1 FROM send_sealing_intents i WHERE i.package_send_attempt_id=a.attempt_id
 AND i.org_id=a.org_id AND i.document_id=a.document_id))::boolean AS has_active_intent
FROM document_package_send_attempts_v1 a
WHERE a.attempt_id=$1::uuid AND a.org_id=$2::uuid AND a.document_id=$3::uuid
`

const legacyPackageTerminalAttemptSQL619 = `-- name: TerminalizeDocumentPackageSendAttemptV1 :one
UPDATE document_package_send_attempts_v1 SET terminal_outcome=$1::text,terminal_at=clock_timestamp()
WHERE attempt_id=$2::uuid AND org_id=$3::uuid AND document_id=$4::uuid
 AND manifest_sha256=$5::bytea AND legal_commitment_sha256=$6::bytea
 AND terminal_outcome IS NULL AND $1::text IN ('completed','aborted')
RETURNING attempt_id, org_id, document_id, package_id, capture_revision, previous_revision, manifest_bytes, member_count, pdf_bytes, pdf_pages, captured_root_updated_at, captured_draft_generation, manifest_sha256, legal_commitment_sha256, actor_user_id, article13_notice_epoch_at, retain_until, retention_started_at, retention_completed_at, terminal_outcome, terminal_at, created_at
`

const legacyPackageDeleteIntentSQL619 = `-- name: DeleteDocumentPackageSealingIntentV1 :execrows
DELETE FROM send_sealing_intents i USING document_package_send_attempts_v1 a
WHERE a.attempt_id=$1::uuid AND a.org_id=$2::uuid AND a.document_id=$3::uuid
 AND a.manifest_sha256=$4::bytea AND a.legal_commitment_sha256=$5::bytea
 AND a.terminal_outcome IS NOT NULL AND i.package_send_attempt_id=a.attempt_id AND i.org_id=a.org_id AND i.document_id=a.document_id
`

type legacyPackageAttemptRow619 struct {
	AttemptID               uuid.UUID          `json:"attempt_id"`
	OrgID                   uuid.UUID          `json:"org_id"`
	DocumentID              uuid.UUID          `json:"document_id"`
	PackageID               uuid.UUID          `json:"package_id"`
	CaptureRevision         int64              `json:"capture_revision"`
	PreviousRevision        int64              `json:"previous_revision"`
	ManifestBytes           int32              `json:"manifest_bytes"`
	MemberCount             int16              `json:"member_count"`
	PdfBytes                int64              `json:"pdf_bytes"`
	PdfPages                int32              `json:"pdf_pages"`
	CapturedRootUpdatedAt   pgtype.Timestamptz `json:"captured_root_updated_at"`
	CapturedDraftGeneration int64              `json:"captured_draft_generation"`
	ManifestSha256          []byte             `json:"manifest_sha256"`
	LegalCommitmentSha256   []byte             `json:"legal_commitment_sha256"`
	ActorUserID             uuid.UUID          `json:"actor_user_id"`
	Article13NoticeEpochAt  pgtype.Timestamptz `json:"article13_notice_epoch_at"`
	RetainUntil             pgtype.Timestamptz `json:"retain_until"`
	RetentionStartedAt      pgtype.Timestamptz `json:"retention_started_at"`
	RetentionCompletedAt    pgtype.Timestamptz `json:"retention_completed_at"`
	TerminalOutcome         pgtype.Text        `json:"terminal_outcome"`
	TerminalAt              pgtype.Timestamptz `json:"terminal_at"`
	CreatedAt               pgtype.Timestamptz `json:"created_at"`
}

func legacyPackageScan619(row pgx.Row, active *bool) (*legacyPackageAttemptRow619, error) {
	var result legacyPackageAttemptRow619
	targets := []any{&result.AttemptID, &result.OrgID, &result.DocumentID, &result.PackageID, &result.CaptureRevision, &result.PreviousRevision, &result.ManifestBytes, &result.MemberCount, &result.PdfBytes, &result.PdfPages, &result.CapturedRootUpdatedAt, &result.CapturedDraftGeneration, &result.ManifestSha256, &result.LegalCommitmentSha256, &result.ActorUserID, &result.Article13NoticeEpochAt, &result.RetainUntil, &result.RetentionStartedAt, &result.RetentionCompletedAt, &result.TerminalOutcome, &result.TerminalAt, &result.CreatedAt}
	if active != nil {
		targets = append(targets, active)
	}
	err := row.Scan(targets...)
	return &result, err
}

func legacyPackageCreate619(ctx context.Context, tx pgx.Tx, id uuid.UUID, c pdfadmission.HTMLSendPackageCaptureMetadataV1) (*legacyPackageAttemptRow619, error) {
	return legacyPackageScan619(tx.QueryRow(ctx, legacyPackageCreateAttemptSQL619,
		id, c.PackageID, c.Revision, c.OrgID, c.DocumentID, pgtype.Timestamptz{Time: c.RootUpdatedAt, Valid: true},
		c.DraftGeneration, c.PreviousRevision, c.ManifestBytes, c.CanonicalSHA256[:], c.CommitmentSHA256[:], c.MemberCount, c.PDFBytes, c.PDFPages, c.CreatedBy), nil)
}

func legacyPackageRead619(ctx context.Context, db generated.DBTX, arg generated.InspectDocumentPackageSendAttemptV1Params) (*legacyPackageAttemptRow619, bool, error) {
	var active bool
	row, err := legacyPackageScan619(db.QueryRow(ctx, legacyPackageInspectAttemptSQL619, arg.AttemptID, arg.OrgID, arg.DocumentID), &active)
	return row, active, err
}

func packageLegacyTerminal619(ctx context.Context, tx pgx.Tx, m pdfadmission.HTMLSendPackageIntentMetadataV1) error {
	if _, err := legacyPackageScan619(tx.QueryRow(ctx, legacyPackageTerminalAttemptSQL619,
		"completed", m.AttemptID, m.Capture.OrgID, m.Capture.DocumentID, m.Capture.CanonicalSHA256[:], m.Capture.CommitmentSHA256[:]), nil); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, legacyPackageDeleteIntentSQL619, legacyPackageArgs619(m)...)
	if err == nil && result.RowsAffected() != 1 {
		return errors.New("synthetic completion did not delete exact intent")
	}
	return err
}

func packageLegacyInspect619(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, active bool, outcome string) {
	t.Helper()
	row, hasActive, e := legacyPackageRead619(q.f.ctx, q.f.pool, generated.InspectDocumentPackageSendAttemptV1Params{AttemptID: m.AttemptID, OrgID: q.f.org, DocumentID: m.Capture.DocumentID})
	if e != nil || row.AttemptID != m.AttemptID || row.OrgID != q.f.org || row.DocumentID != m.Capture.DocumentID || row.PackageID != m.Capture.PackageID || row.CaptureRevision != m.Capture.Revision || row.PreviousRevision != m.Capture.PreviousRevision || row.ManifestBytes != m.Capture.ManifestBytes || row.MemberCount != m.Capture.MemberCount || row.PdfBytes != m.Capture.PDFBytes || row.PdfPages != m.Capture.PDFPages || row.CapturedDraftGeneration != m.Capture.DraftGeneration || !row.CapturedRootUpdatedAt.Time.Equal(m.Capture.RootUpdatedAt) || hasActive != active || row.TerminalOutcome.String != outcome || row.TerminalOutcome.Valid != (outcome != "") || !row.Article13NoticeEpochAt.Time.Equal(m.Article13NoticeEpochAt) || !row.RetainUntil.Time.Equal(m.RetainUntil) {
		t.Fatal("exact attempt inspection differs", row, e)
	}
	if !active && !row.TerminalAt.Valid {
		t.Fatal("terminal history lost")
	}
	wrong := generated.InspectDocumentPackageSendAttemptV1Params{AttemptID: uuid.New(), OrgID: q.f.org, DocumentID: m.Capture.DocumentID}
	if _, _, e = legacyPackageRead619(q.f.ctx, q.f.pool, wrong); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("missing exact attempt inspected as an existing winner", e)
	}
	wrong.AttemptID = m.AttemptID
	wrong.OrgID = uuid.New()
	if _, _, e = legacyPackageRead619(q.f.ctx, q.f.pool, wrong); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("foreign tenant read attempt history", e)
	}
}
