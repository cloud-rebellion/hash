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
	a, err := generated.New(tx).CreateDocumentPackageSendAttemptV1(q.f.ctx, generated.CreateDocumentPackageSendAttemptV1Params{
		AttemptID: id, PackageID: c.PackageID, CaptureRevision: c.Revision, OrgID: c.OrgID, DocumentID: c.DocumentID,
		ExpectedRootUpdatedAt: pgtype.Timestamptz{Time: c.RootUpdatedAt, Valid: true}, ExpectedDraftGeneration: c.DraftGeneration,
		ExpectedPreviousRevision: c.PreviousRevision, ExpectedManifestBytes: c.ManifestBytes, ExpectedManifestSha256: c.CanonicalSHA256[:],
		ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], ExpectedMemberCount: c.MemberCount, ExpectedPdfBytes: c.PDFBytes,
		ExpectedPdfPages: c.PDFPages, ActorUserID: c.CreatedBy,
	})
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
	if err := packageCompletionSQLTerminal241(q.f.ctx, generated.New(tx), m); err != nil {
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
