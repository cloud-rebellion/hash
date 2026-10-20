//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/recoveryinventory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// These fixtures exercise native PostgreSQL persistence, not real object/PDF
// validation, resource admission, attachment endpoints, Send or signing consent.
func captureMember219(p generated.InsertDocumentAttachmentDraftV1Params) documentpackage.MemberV1 {
	m := documentpackage.MemberV1{DocumentID: p.MemberDocumentID, Title: p.Title, Category: p.Category,
		PDF:    documentpackage.PDFPinV1{Key: p.PdfKey, VersionID: p.PdfVersionID, SHA256: hex.EncodeToString(p.PdfSha256), Bytes: p.PdfBytes, Pages: p.PdfPages},
		Source: documentpackage.SourcePinV1{Kind: p.SourceKind, CommitmentSHA256: hex.EncodeToString(p.SourceCommitment), OriginCommitmentSHA256: hex.EncodeToString(p.OriginCommitment)}}
	if p.MaterializationID.Valid {
		m.Source.Materialization = &documentpackage.MaterializationPinV1{ID: p.MaterializationID.Bytes, Sequence: p.MaterializationSequence.Int32}
	}
	return m
}
func captureInput219(t *testing.T, f lifecycleAuthorizationFixture, p *generated.DocumentPackagesV1, revision, previous int64) generated.AppendDocumentPackageCaptureV1Params {
	t.Helper()
	root, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: p.DocumentID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	main := captureMember219(packagePin218(t, p, root, 1))
	main.Category = "Agreement"
	rows, err := f.q.ListDocumentAttachmentDraftsV1(f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: f.org, ExpectedGeneration: p.DraftGeneration})
	if err != nil {
		t.Fatal(err)
	}
	annexes := make([]documentpackage.MemberV1, 0, len(rows))
	for _, a := range rows {
		annexes = append(annexes, captureMember219(generated.InsertDocumentAttachmentDraftV1Params{MemberDocumentID: a.MemberDocumentID, Title: a.Title, Category: a.Category, PdfKey: a.PdfKey, PdfVersionID: a.PdfVersionID, PdfSha256: a.PdfSha256, PdfBytes: a.PdfBytes, PdfPages: a.PdfPages, SourceKind: a.SourceKind, SourceCommitment: a.SourceCommitment, OriginCommitment: a.OriginCommitment, MaterializationID: a.MaterializationID, MaterializationSequence: a.MaterializationSequence}))
	}
	m, err := documentpackage.NewManifestV1(documentpackage.InputV1{Binding: documentpackage.BindingV1{OrgID: f.org, DocumentID: root.ID, PackageID: p.ID, Revision: revision}, Main: main, Annexes: annexes})
	if err != nil {
		t.Fatal(err)
	}
	c, err := documentpackage.NewCaptureV1(m, documentpackage.CaptureGuardV1{RootUpdatedAt: root.UpdatedAt.Time, DraftGeneration: p.DraftGeneration, PreviousRevision: previous})
	if err != nil {
		t.Fatal(err)
	}
	h := c.Header()
	obj, _ := hex.DecodeString(h.CanonicalSHA256)
	legal, _ := hex.DecodeString(h.CommitmentSHA256)
	return generated.AppendDocumentPackageCaptureV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: root.ID, Revision: revision, ExpectedPreviousRevision: previous, ExpectedUpdatedAt: root.UpdatedAt, ExpectedGeneration: p.DraftGeneration, Manifest: c.Manifest().CanonicalJSON(), ManifestSha256: obj, LegalCommitmentSha256: legal, CreatedBy: f.user.ID}
}
func captureRehash219(in *generated.AppendDocumentPackageCaptureV1Params) {
	a := sha256.Sum256(in.Manifest)
	b := sha256.Sum256(append([]byte("hash:legal-package-manifest:v1\x00"), in.Manifest...))
	in.ManifestSha256 = a[:]
	in.LegalCommitmentSha256 = b[:]
}
func captureLoad219(t *testing.T, f lifecycleAuthorizationFixture, p *generated.DocumentPackagesV1, revision int64) (*documentpackage.CaptureV1, []*generated.DocumentPackageCaptureMembersV1) {
	t.Helper()
	h, err := f.q.GetDocumentPackageCaptureHeaderV1(f.ctx, generated.GetDocumentPackageCaptureHeaderV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: p.DocumentID, Revision: revision})
	if err != nil {
		t.Fatal(err)
	}
	if h.ManifestBytes < 1 || h.ManifestBytes > 65536 || h.MemberCount < 1 || h.MemberCount > 17 {
		t.Fatal("header bound")
	}
	raw, err := f.q.GetDocumentPackageCapturePayloadV1(f.ctx, generated.GetDocumentPackageCapturePayloadV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: p.DocumentID, Revision: revision, ExpectedManifestSha256: h.ManifestSha256, ExpectedLegalCommitmentSha256: h.LegalCommitmentSha256, ExpectedManifestBytes: h.ManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	c, err := documentpackage.DecodeCaptureV1(raw, documentpackage.CaptureHeaderV1{Binding: documentpackage.BindingV1{OrgID: f.org, DocumentID: p.DocumentID, PackageID: p.ID, Revision: revision}, Guard: documentpackage.CaptureGuardV1{RootUpdatedAt: h.CapturedRootUpdatedAt.Time, DraftGeneration: h.CapturedDraftGeneration, PreviousRevision: h.PreviousRevision}, ManifestBytes: h.ManifestBytes, MemberCount: h.MemberCount, PDFBytes: h.PdfBytes, PDFPages: h.PdfPages, CanonicalSHA256: hex.EncodeToString(h.ManifestSha256), CommitmentSHA256: hex.EncodeToString(h.LegalCommitmentSha256)})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.q.ListDocumentPackageCaptureMembersV1(f.ctx, generated.ListDocumentPackageCaptureMembersV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: p.DocumentID, Revision: revision, ExpectedManifestSha256: h.ManifestSha256, ExpectedLegalCommitmentSha256: h.LegalCommitmentSha256, ExpectedMemberCount: h.MemberCount})
	if err != nil || len(rows) != int(h.MemberCount) {
		t.Fatal("inventory cardinality", err)
	}
	expected := append([]documentpackage.MemberV1{c.Manifest().Main()}, c.Manifest().Annexes()...)
	for i, a := range rows {
		actual := captureMember219(generated.InsertDocumentAttachmentDraftV1Params{MemberDocumentID: a.MemberDocumentID, Title: a.Title, Category: a.Category, PdfKey: a.PdfKey, PdfVersionID: a.PdfVersionID, PdfSha256: a.PdfSha256, PdfBytes: a.PdfBytes, PdfPages: a.PdfPages, SourceKind: a.SourceKind, SourceCommitment: a.SourceCommitment, OriginCommitment: a.OriginCommitment, MaterializationID: a.MaterializationID, MaterializationSequence: a.MaterializationSequence})
		if a.MemberPosition != int16(i) || !reflect.DeepEqual(actual, expected[i]) {
			t.Fatal("derived inventory differs", i)
		}
	}
	return c, rows
}
func TestDocumentPackageCapturePersistenceV1E2E(t *testing.T) {
	f, html := htmlMaterializationFixtureE2E(t)
	html = packageFreshSyntheticReport222(t, f, html)
	var err error
	html, err = f.q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: html.ID, OrgID: f.org, ExpectedUpdatedAt: html.UpdatedAt, ExpectedPdfSha256: html.PdfSha256, ReviewedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	root := packagePDF218(t, f, "Café / Cafe\u0301 agreement")
	a := packagePDF218(t, f, "DPA imported")
	p := packageHeader218(t, f, root)
	if _, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, a, 3)); err != nil {
		t.Fatal(err)
	}
	p = packageFresh218(t, f, p.ID)
	if _, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, html, 9)); err != nil {
		t.Fatal(err)
	}
	p = packageFresh218(t, f, p.ID)
	input := captureInput219(t, f, p, 1, 0)
	before := packageSnapshot218(t, f, p.ID)
	t.Run("exact bytes hashes ordered gapped pins and no clock mutation", func(t *testing.T) {
		stored, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stored.Manifest, input.Manifest) || stored.MemberCount != 3 || !bytes.Equal(stored.ManifestSha256, input.ManifestSha256) || !bytes.Equal(stored.LegalCommitmentSha256, input.LegalCommitmentSha256) {
			t.Fatal("stored bytes or hashes differ")
		}
		c, _ := captureLoad219(t, f, p, 1)
		if !bytes.Equal(c.Manifest().CanonicalJSON(), input.Manifest) || packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("capture changed draft clock/list")
		}
	})
	t.Run("scoped fixed header and hash bound payload", func(t *testing.T) {
		for _, x := range []generated.GetDocumentPackageCaptureHeaderV1Params{{PackageID: p.ID, OrgID: uuid.New(), DocumentID: root.ID, Revision: 1}, {PackageID: uuid.New(), OrgID: f.org, DocumentID: root.ID, Revision: 1}, {PackageID: p.ID, OrgID: f.org, DocumentID: uuid.New(), Revision: 1}, {PackageID: p.ID, OrgID: f.org, DocumentID: root.ID, Revision: 2}} {
			if _, err := f.q.GetDocumentPackageCaptureHeaderV1(f.ctx, x); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal(err)
			}
		}
		for _, bad := range []generated.GetDocumentPackageCapturePayloadV1Params{{PackageID: p.ID, OrgID: f.org, DocumentID: root.ID, Revision: 1, ExpectedManifestSha256: input.LegalCommitmentSha256, ExpectedLegalCommitmentSha256: input.ManifestSha256, ExpectedManifestBytes: int32(len(input.Manifest))}, {PackageID: p.ID, OrgID: f.org, DocumentID: root.ID, Revision: 1, ExpectedManifestSha256: input.ManifestSha256, ExpectedLegalCommitmentSha256: input.LegalCommitmentSha256, ExpectedManifestBytes: int32(len(input.Manifest) - 1)}} {
			if _, err := f.q.GetDocumentPackageCapturePayloadV1(f.ctx, bad); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal(err)
			}
		}
	})
	t.Run("stale root generation predecessor actor and binding refuse atomically", func(t *testing.T) {
		fresh := captureInput219(t, f, p, 2, 1)
		changes := map[string]func(*generated.AppendDocumentPackageCaptureV1Params){"clock": func(x *generated.AppendDocumentPackageCaptureV1Params) {
			x.ExpectedUpdatedAt.Time = x.ExpectedUpdatedAt.Time.Add(-time.Microsecond)
		}, "generation": func(x *generated.AppendDocumentPackageCaptureV1Params) { x.ExpectedGeneration++ }, "predecessor": func(x *generated.AppendDocumentPackageCaptureV1Params) { x.ExpectedPreviousRevision = 0 }, "actor": func(x *generated.AppendDocumentPackageCaptureV1Params) { x.CreatedBy = uuid.New() }, "binding": func(x *generated.AppendDocumentPackageCaptureV1Params) { x.Revision++ }, "digest": func(x *generated.AppendDocumentPackageCaptureV1Params) {
			x.ManifestSha256 = bytes.Clone(x.LegalCommitmentSha256)
		}, "main pin": func(x *generated.AppendDocumentPackageCaptureV1Params) {
			x.Manifest = []byte(strings.Replace(string(x.Manifest), root.PdfStorageVersionID.String, "wrong-version", 1))
			captureRehash219(x)
		}, "annex label": func(x *generated.AppendDocumentPackageCaptureV1Params) {
			x.Manifest = []byte(strings.Replace(string(x.Manifest), "DPA imported", "Different terms", 1))
			captureRehash219(x)
		}}
		for name, mutate := range changes {
			t.Run(name, func(t *testing.T) {
				bad := fresh
				bad.Manifest = bytes.Clone(fresh.Manifest)
				mutate(&bad)
				if _, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, bad); err == nil {
					t.Fatal("accepted stale/different capture")
				}
				head, err := f.q.GetDocumentPackageCaptureHeadV1(f.ctx, generated.GetDocumentPackageCaptureHeadV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: root.ID})
				if err != nil || head != 1 || packageSnapshot218(t, f, p.ID) != before {
					t.Fatal("refusal changed history", head, err)
				}
			})
		}
	})
	t.Run("row mutation and divergent inventory refuse", func(t *testing.T) {
		for _, sql := range []string{"UPDATE document_package_captures_v1 SET pdf_pages=1 WHERE package_id=$1", "DELETE FROM document_package_captures_v1 WHERE package_id=$1", "UPDATE document_package_capture_members_v1 SET title='Changed' WHERE package_id=$1", "DELETE FROM document_package_capture_members_v1 WHERE package_id=$1", "INSERT INTO document_package_capture_members_v1 SELECT package_id,revision,org_id,16,member_document_id,title,category,pdf_key,pdf_version_id,pdf_sha256,pdf_bytes,pdf_pages,source_kind,source_commitment,origin_commitment,materialization_id,materialization_sequence FROM document_package_capture_members_v1 WHERE package_id=$1 AND member_position=0"} {
			_, err := f.pool.Exec(f.ctx, sql, p.ID)
			packageExpectPG218(t, err, "23514")
		}
		captureLoad219(t, f, p, 1)
	})
	t.Run("root edit with unchanged generation invalidates old capture request", func(t *testing.T) {
		stale := captureInput219(t, f, p, 2, 1)
		if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET updated_at=updated_at+interval '1 microsecond',name='Later main title' WHERE id=$1", root.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, stale); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		c, _ := captureLoad219(t, f, p, 1)
		if !bytes.Equal(c.Manifest().CanonicalJSON(), input.Manifest) {
			t.Fatal("history followed root edit")
		}
	})
	t.Run("detached historical source remains in purge privacy and recovery", func(t *testing.T) {
		if _, err := f.q.DeleteDocumentAttachmentDraftV1(f.ctx, generated.DeleteDocumentAttachmentDraftV1Params{PackageID: p.ID, OrgID: f.org, MemberDocumentID: a.ID, ExpectedGeneration: p.DraftGeneration}); err != nil {
			t.Fatal(err)
		}
		p = packageFresh218(t, f, p.ID)
		if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET pdf_storage_key=$2,pdf_storage_version_id='later',updated_at=clock_timestamp() WHERE id=$1", a.ID, a.PdfStorageKey.String+".later"); err != nil {
			t.Fatal(err)
		}
		shared, err := f.q.HasOtherDocumentSourceReferences(f.ctx, generated.HasOtherDocumentSourceReferencesParams{DocumentID: a.ID, ObjectKey: a.PdfStorageKey.String})
		if err != nil || !shared {
			t.Fatal("history object ref lost", err)
		}
		held, err := f.q.HasRetainedDraftEvidenceForPurge(f.ctx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: a.ID, OrgID: f.org})
		if err != nil || !held {
			t.Fatal("history subject ref lost", err)
		}
		privacy, err := f.q.HasHTMLAuthoringDataForDSR(f.ctx, f.org)
		if err != nil || !privacy {
			t.Fatal("privacy lost", err)
		}
		signing, err := f.q.HasRetainedDraftSigningEvidence(f.ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: root.ID, OrgID: f.org})
		if err != nil || signing {
			t.Fatal("draft capture became signing evidence", err)
		}
		sql, err := os.ReadFile("../../ops/recovery-object-inventory.sql")
		if err != nil {
			t.Fatal(err)
		}
		inventoryTx, err := recoveryinventory.Begin(f.ctx, f.pool)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := recoveryinventory.Rollback(inventoryTx); err != nil {
				t.Error("close canonical inventory snapshot", err)
			}
		}()
		rows, err := inventoryTx.Query(f.ctx, string(sql))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for rows.Next() {
			v, err := rows.Values()
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if fmt.Sprint(v[0]) == base64.StdEncoding.EncodeToString([]byte(a.PdfStorageKey.String)) {
				found = strings.Contains(fmt.Sprint(v), "draft_package_capture_pdf") && strings.Contains(fmt.Sprint(v), a.PdfStorageVersionID.String)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil || !found {
			t.Fatal("history recovery inventory", found, err)
		}
		if err := recoveryinventory.Rollback(inventoryTx); err != nil {
			t.Fatal("close canonical inventory snapshot", err)
		}
		c, _ := captureLoad219(t, f, p, 1)
		if !bytes.Equal(c.Manifest().CanonicalJSON(), input.Manifest) {
			t.Fatal("history followed detach/source edit")
		}
		fresh := captureInput219(t, f, p, 9007199254740993, 1)
		if _, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, fresh); err != nil {
			t.Fatal(err)
		}
		c, _ = captureLoad219(t, f, p, 9007199254740993)
		if c.Header().MemberCount != 2 {
			t.Fatal("fresh membership did not change")
		}
		latest := captureInput219(t, f, p, math.MaxInt64, 9007199254740993)
		if _, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, latest); err != nil {
			t.Fatal(err)
		}
		captureLoad219(t, f, p, math.MaxInt64)
	})
}

func TestDocumentPackageCaptureTransactionV1E2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	root := packagePDF218(t, f, "Concurrent main")
	p := packageHeader218(t, f, root)
	t.Run("uncommitted rollback leaves no capture or members", func(t *testing.T) {
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx)
		if _, err = f.q.WithTx(tx).AppendDocumentPackageCaptureV1(f.ctx, captureInput219(t, f, p, 1, 0)); err != nil {
			t.Fatal(err)
		}
		if err = tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
		head, err := f.q.GetDocumentPackageCaptureHeadV1(f.ctx, generated.GetDocumentPackageCaptureHeadV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: root.ID})
		if err != nil || head != 0 {
			t.Fatal(head, err)
		}
		var n int
		if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM document_package_capture_members_v1 WHERE package_id=$1", p.ID).Scan(&n); err != nil || n != 0 {
			t.Fatal(n, err)
		}
	})
	t.Run("repeatable read stale head cannot branch", func(t *testing.T) {
		one, two := captureInput219(t, f, p, 1, 0), captureInput219(t, f, p, 2, 0)
		tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx)
		if _, err = f.q.WithTx(tx).GetDocumentPackageCaptureHeadV1(f.ctx, generated.GetDocumentPackageCaptureHeadV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: root.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err = f.q.AppendDocumentPackageCaptureV1(f.ctx, one); err != nil {
			t.Fatal(err)
		}
		_, err = f.q.WithTx(tx).AppendDocumentPackageCaptureV1(f.ctx, two)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || (pe.Code != "23505" && pe.Code != "40001") {
			t.Fatal("stale snapshot branched", err)
		}
	})
	t.Run("overlapping distinct revisions share one predecessor", func(t *testing.T) {
		// A new root makes both competing proposals start from an empty head.
		r := packagePDF218(t, f, "Overlapping root")
		pp := packageHeader218(t, f, r)
		one, two := captureInput219(t, f, pp, 1, 0), captureInput219(t, f, pp, 2, 0)
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx)
		if _, err = f.q.WithTx(tx).AppendDocumentPackageCaptureV1(f.ctx, one); err != nil {
			t.Fatal(err)
		}
		other, err := f.pool.Acquire(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		pid := other.Conn().PgConn().PID()
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { _, e := generated.New(other).AppendDocumentPackageCaptureV1(ctx, two); done <- e }()
		joined := false
		defer func() {
			cancel()
			_ = tx.Rollback(f.ctx) // Release the first lock before waiting on failure.
			if !joined {
				select {
				case <-done:
					joined = true
				case <-time.After(5 * time.Second):
					t.Error("competing query failed to join after cancellation")
					return
				}
			}
			other.Release() // Never reuse the connection before the query joins.
		}()
		deadline := time.Now().Add(3 * time.Second)
		blocked := false
		for time.Now().Before(deadline) {
			var wait string
			err = f.pool.QueryRow(f.ctx, "SELECT coalesce(wait_event_type,'') FROM pg_stat_activity WHERE pid=$1", pid).Scan(&wait)
			if err != nil {
				t.Fatal(err)
			}
			if wait == "Lock" {
				blocked = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !blocked {
			t.Fatal("competing writer did not reach actual lock")
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-done:
			joined = true
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || (pe.Code != "23514" && pe.Code != "23505") {
				t.Fatal("competing writer did not reach predecessor refusal", err)
			}
		case <-ctx.Done():
			t.Fatal("competing writer not joined")
		}
		captureLoad219(t, f, pp, 1)
		head, err := f.q.GetDocumentPackageCaptureHeadV1(f.ctx, generated.GetDocumentPackageCaptureHeadV1Params{PackageID: pp.ID, OrgID: f.org, DocumentID: r.ID})
		var captures, members int
		if err != nil || head != 1 {
			t.Fatal("competing append changed head", head, err)
		}
		if err = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM document_package_captures_v1 WHERE package_id=$1),(SELECT count(*) FROM document_package_capture_members_v1 WHERE package_id=$1)", pp.ID).Scan(&captures, &members); err != nil || captures != 1 || members != 1 {
			t.Fatal("competing inventory changed", captures, members, err)
		}
	})
}
func TestDocumentPackageCaptureRollbackAndBoundsV1E2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	root := packagePDF218(t, f, "Main-only bounds")
	p := packageHeader218(t, f, root)
	good := captureInput219(t, f, p, 1, 0)

	t.Run("aggregate across two individually valid PDFs", func(t *testing.T) {
		r := packagePDF218(t, f, "Aggregate main")
		a := packagePDF218(t, f, "Aggregate annex")
		pp := packageHeader218(t, f, r)
		pin := packagePin218(t, pp, a, 7)
		pin.PdfBytes = 25 << 20
		pin.PdfPages = 250
		if _, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, pin); err != nil {
			t.Fatal(err)
		}
		pp = packageFresh218(t, f, pp.ID)
		input := captureInput219(t, f, pp, 1, 0)
		for name, bad := range map[string][]byte{"sum bytes": []byte(strings.Replace(string(input.Manifest), "\"bytes\":1234", "\"bytes\":26214401", 1)), "sum pages": []byte(strings.Replace(string(input.Manifest), "\"pages\":1", "\"pages\":251", 1))} {
			t.Run(name, func(t *testing.T) {
				in := input
				in.Manifest = bad
				captureRehash219(&in)
				_, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, in)
				packageExpectPG218(t, err, "23514")
			})
		}
		input.Manifest = []byte(strings.Replace(strings.Replace(string(input.Manifest), "\"bytes\":1234", "\"bytes\":26214400", 1), "\"pages\":1", "\"pages\":250", 1))
		captureRehash219(&input)
		if _, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, input); err != nil {
			t.Fatal("exact combined boundary", err)
		}
		c, _ := captureLoad219(t, f, pp, 1)
		if c.Header().PDFBytes != 50<<20 || c.Header().PDFPages != 500 || c.Header().MemberCount != 2 {
			t.Fatal("combined boundary differs")
		}
	})

	t.Run("aggregate byte page and payload bounds are enforced in SQL", func(t *testing.T) {
		for name, bad := range map[string][]byte{"bytes": []byte(strings.Replace(string(good.Manifest), "\"bytes\":1234", "\"bytes\":52428801", 1)), "pages": []byte(strings.Replace(string(good.Manifest), "\"pages\":1", "\"pages\":501", 1)), "payload": bytes.Repeat([]byte(" "), 65537)} {
			t.Run(name, func(t *testing.T) {
				in := good
				in.Manifest = bad
				captureRehash219(&in)
				if _, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, in); err == nil {
					t.Fatal("overbound admitted")
				}
			})
		}
		in := good
		in.Manifest = []byte(strings.Replace(strings.Replace(string(good.Manifest), "\"bytes\":1234", "\"bytes\":52428800", 1), "\"pages\":1", "\"pages\":500", 1))
		captureRehash219(&in)
		if _, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, in); err != nil {
			t.Fatal("exact aggregate boundary", err)
		}
		c, _ := captureLoad219(t, f, p, 1)
		if c.Header().PDFBytes != 52428800 || c.Header().PDFPages != 500 {
			t.Fatal("boundary totals")
		}
	})
	t.Run("occupied capture rollback and empty header disposal refuse", func(t *testing.T) {
		cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
		if err != nil {
			t.Fatal(err)
		}
		db := stdlib.OpenDB(*cfg)
		defer db.Close()
		if err = mdb.RunMigrationsDownToContext(f.ctx, db, 100); err == nil {
			t.Fatal("occupied capture rollback erased history")
		}
		removed, err := f.q.DeleteEmptyDocumentPackageV1(f.ctx, generated.DeleteEmptyDocumentPackageV1Params{PackageID: p.ID, OrgID: f.org, ExpectedGeneration: p.DraftGeneration})
		if err != nil || removed != 0 {
			t.Fatal("history header disposed", removed, err)
		}
		captureLoad219(t, f, p, 1)
		if err = mdb.RunMigrationsContext(f.ctx, db); err != nil {
			t.Fatal("restore current schema after occupied capture refusal", err)
		}
	})
	// Empty Down/reapply is covered after synthetic fixture disposal by the V99
	// rollback test, which first rolls empty102/101/100 down to99, retains occupied99's
	// refusal, then reapplies all and verifies max migration106.
	digest, versions, err := mdb.EmbeddedMigrationsIdentity()
	if err != nil || len(versions) != 106 || versions[105] != 106 {
		t.Fatal(err)
	}
	t.Logf("capture migration v106 %s", digest)
}
