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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recoveryinventory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

// Actual PostgreSQL persistence/protection tests. All PDF tuples and measured
// size/page declarations are synthetic. No storage, scanner, renderer, package
// consent, authorization adapter or usable attachment workflow is asserted.
func packagePDF218(t *testing.T, f lifecycleAuthorizationFixture, label string) *generated.Document {
	t.Helper()
	sum := sha256.Sum256([]byte("synthetic selected PDF " + label))
	d, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: label,
		PdfStorageKey: pgtype.Text{String: "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}, PdfSha256: sum[:],
		PdfStorageVersionID: pgtype.Text{String: " synthetic+/=" + uuid.NewString() + " ", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	return packageFreshSyntheticReport222(t, f, d)
}

// Fresh synthetic persistence fixture only: this measures its actual tiny
// stored report through M93; it is not PDF intake/admission eligibility.
func packageFreshSyntheticReport222(t *testing.T, f lifecycleAuthorizationFixture, d *generated.Document) *generated.Document {
	t.Helper()
	if len(d.MetadataRedactionReport) == 0 {
		if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET metadata_redaction_report='{}'::jsonb,updated_at=GREATEST(clock_timestamp(),updated_at+interval '1 microsecond') WHERE id=$1 AND org_id=$2", d.ID, f.org); err != nil {
			t.Fatal(err)
		}
		var err error
		d, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.q.MeasureSignerDocumentReportV1(f.ctx, generated.MeasureSignerDocumentReportV1Params{DocumentID: d.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	return d
}
func packageHeader218(t *testing.T, f lifecycleAuthorizationFixture, root *generated.Document) *generated.DocumentPackagesV1 {
	t.Helper()
	p, err := f.q.CreateDocumentPackageV1(f.ctx, generated.CreateDocumentPackageV1Params{PackageID: uuid.New(), OrgID: f.org, DocumentID: root.ID, CreatedBy: f.user.ID, ExpectedUpdatedAt: root.UpdatedAt})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func packagePin218(t *testing.T, p *generated.DocumentPackagesV1, d *generated.Document, ordinal int16) generated.InsertDocumentAttachmentDraftV1Params {
	t.Helper()
	in := generated.InsertDocumentAttachmentDraftV1Params{PackageID: p.ID, OrgID: p.OrgID, ExpectedGeneration: p.DraftGeneration, MemberDocumentID: d.ID, Ordinal: ordinal,
		Title: d.Name, Category: "Custom business terms", PdfKey: d.PdfStorageKey.String, PdfVersionID: d.PdfStorageVersionID.String, PdfSha256: bytes.Clone(d.PdfSha256), PdfBytes: 1234, PdfPages: 1, SourceKind: "pdf-import"}
	if len(d.HtmlSourceJson) != 0 {
		var origin, current struct{ Commitment string }
		if err := json.Unmarshal(d.HtmlSourceJson, &origin); err != nil {
			t.Fatal(err)
		}
		current = origin
		if len(d.HtmlCurrentSourceJson) != 0 {
			if err := json.Unmarshal(d.HtmlCurrentSourceJson, &current); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		in.OriginCommitment, err = hex.DecodeString(origin.Commitment)
		if err != nil {
			t.Fatal(err)
		}
		in.SourceCommitment, err = hex.DecodeString(current.Commitment)
		if err != nil {
			t.Fatal(err)
		}
		in.SourceKind = "html-origin"
		if d.HtmlCurrentMaterializationID.Valid {
			in.SourceKind = "html-materialization"
			in.MaterializationID = d.HtmlCurrentMaterializationID
			in.MaterializationSequence = d.HtmlCurrentMaterializationSequence
			in.PdfPages = d.HtmlCurrentPageCount.Int32
		}
	}
	return in
}
func packageFresh218(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) *generated.DocumentPackagesV1 {
	t.Helper()
	p, err := f.q.LockDocumentPackageV1(f.ctx, generated.LockDocumentPackageV1Params{PackageID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func packageExpectPG218(t *testing.T, err error, code string) {
	t.Helper()
	var e *pgconn.PgError
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("expected PostgreSQL %s, got %v", code, err)
	}
}
func packageSnapshot218(t *testing.T, f lifecycleAuthorizationFixture, p uuid.UUID) string {
	t.Helper()
	var out string
	if err := f.pool.QueryRow(f.ctx,
		"SELECT jsonb_build_object('header',(SELECT to_jsonb(p) FROM document_packages_v1 p WHERE id=$1),'members',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY ordinal),'[]'::jsonb) FROM document_attachment_drafts_v1 a WHERE package_id=$1),'root_clock',(SELECT d.updated_at FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id WHERE p.id=$1))::text", p).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDocumentAttachmentDraftPersistenceAndSendGuardV1E2E(t *testing.T) {
	digest, versions, err := mdb.EmbeddedMigrationsIdentity()
	if err != nil || len(versions) != 106 || versions[len(versions)-1] != 106 {
		t.Fatal("embedded migration inventory", err)
	}
	if expected := os.Getenv("HASH_E2E_EXPECT_MIGRATION_SHA"); expected != "" && expected != digest {
		t.Fatal("embedded migration identity differs from fixture source")
	}
	t.Logf("embedded migration v106 %s", digest)
	f, html := htmlMaterializationFixtureE2E(t)
	html = packageFreshSyntheticReport222(t, f, html)
	root := packagePDF218(t, f, "Main agreement")
	imported := packagePDF218(t, f, "DPA – imported")
	p := packageHeader218(t, f, root)
	t.Run("empty set preserves legacy sealing", func(t *testing.T) {
		header, err := f.q.GetHTMLSendBrandingInputHeaderV1(f.ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: root.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.q.FreezeHTMLSendBrandingV1(f.ctx, htmlSendFreezeFixtureV1(header)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.q.BeginDocumentSendSealing(f.ctx, generated.BeginDocumentSendSealingParams{ID: root.ID, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.q.AbortDocumentSendSealing(f.ctx, generated.AbortDocumentSendSealingParams{ID: root.ID, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("foreign and stale generation refuse atomically", func(t *testing.T) {
		in := packagePin218(t, p, imported, 1)
		before := packageSnapshot218(t, f, p.ID)
		in.OrgID = uuid.New()
		if _, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, in); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		in.OrgID = f.org
		in.ExpectedGeneration++
		if _, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, in); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		if packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("refusal changed inventory or root clock")
		}
	})
	t.Run("actual foreign source and actor plus wrong owned pins refuse", func(t *testing.T) {
		foreignOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Other attachment tenant", Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		foreignUser, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Name: "Other sender", Email: uuid.NewString() + "@attachment.test", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
		if err != nil {
			t.Fatal(err)
		}
		foreign := f
		foreign.org, foreign.user = foreignOrg.ID, foreignUser
		foreignDoc := packagePDF218(t, foreign, "Other tenant NDA")
		before := packageSnapshot218(t, f, p.ID)
		input := packagePin218(t, p, foreignDoc, 1)
		if _, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, input); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("foreign source selection: %v", err)
		}
		freshRoot := packagePDF218(t, f, "Foreign actor target")
		_, err = f.q.CreateDocumentPackageV1(f.ctx, generated.CreateDocumentPackageV1Params{PackageID: uuid.New(), OrgID: f.org, DocumentID: freshRoot.ID, CreatedBy: foreign.user.ID, ExpectedUpdatedAt: freshRoot.UpdatedAt})
		packageExpectPG218(t, err, "23514")
		for _, kind := range []string{"key", "version", "digest", "source kind"} {
			input = packagePin218(t, p, imported, 1)
			switch kind {
			case "key":
				input.PdfKey += ".wrong"
			case "version":
				input.PdfVersionID += "wrong"
			case "digest":
				input.PdfSha256[0] ^= 1
			case "source kind":
				input.SourceKind = "html-origin"
			}
			_, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, input)
			packageExpectPG218(t, err, "23514")
		}
		if packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("tenant or pin refusal changed package")
		}
	})

	in := packagePin218(t, p, imported, 1)
	selected, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if selected.PdfVersionID != in.PdfVersionID {
		t.Fatal("opaque provider version was normalized")
	}
	p = packageFresh218(t, f, p.ID)
	t.Run("unreviewed HTML refuses then exact reviewed materialization succeeds", func(t *testing.T) {
		before := packageSnapshot218(t, f, p.ID)
		_, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, html, 2))
		packageExpectPG218(t, err, "23514")
		if packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("refused HTML selection changed package")
		}
		html, err = f.q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: html.ID, OrgID: f.org, ExpectedUpdatedAt: html.UpdatedAt, ExpectedPdfSha256: html.PdfSha256, ReviewedBy: f.user.ID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, html, 2)); err != nil {
			t.Fatal(err)
		}
	})
	p = packageFresh218(t, f, p.ID)

	t.Run("duplicate ordinal and exact object roll back generation", func(t *testing.T) {
		before := packageSnapshot218(t, f, p.ID)
		different := packagePDF218(t, f, "Duplicate ordinal candidate")
		_, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, different, 1))
		packageExpectPG218(t, err, "23505")
		duplicate, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Same selected object", PdfStorageKey: imported.PdfStorageKey, PdfSha256: imported.PdfSha256, PdfStorageVersionID: imported.PdfStorageVersionID, EvidenceVersionPinsRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		duplicate = packageFreshSyntheticReport222(t, f, duplicate)
		_, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, duplicate, 3))
		packageExpectPG218(t, err, "23505")
		if packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("duplicate refusal advanced generation")
		}
	})
	t.Run("selected pins survive later source edits and cannot be rewritten", func(t *testing.T) {
		old := packageSnapshot218(t, f, p.ID)
		if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET pdf_storage_key=$2,pdf_storage_version_id='new-source-version',pdf_sha256=$3,updated_at=clock_timestamp() WHERE id=$1", imported.ID, imported.PdfStorageKey.String+".changed", bytes.Repeat([]byte{9}, 32)); err != nil {
			t.Fatal(err)
		}
		if packageSnapshot218(t, f, p.ID) != old {
			t.Fatal("live source edit rewrote selected snapshot")
		}
		_, err := f.pool.Exec(f.ctx, "UPDATE document_attachment_drafts_v1 SET pdf_version_id='replaced' WHERE package_id=$1 AND member_document_id=$2", p.ID, imported.ID)
		packageExpectPG218(t, err, "23514")
		if packageSnapshot218(t, f, p.ID) != old {
			t.Fatal("pin replacement refusal changed package")
		}
		shared, err := f.q.HasOtherDocumentSourceReferences(f.ctx, generated.HasOtherDocumentSourceReferencesParams{DocumentID: imported.ID, ObjectKey: imported.PdfStorageKey.String})
		if err != nil || !shared {
			t.Fatalf("selected old object reference missing: %v", err)
		}
		held, err := f.q.HasRetainedDraftEvidenceForPurge(f.ctx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: imported.ID, OrgID: f.org})
		if err != nil || !held {
			t.Fatalf("selected subject purge fence missing: %v", err)
		}
		signing, err := f.q.HasRetainedDraftSigningEvidence(f.ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: root.ID, OrgID: f.org})
		if err != nil || signing {
			t.Fatalf("draft attachments incorrectly became signing evidence: %v", err)
		}
	})
	t.Run("actual canonical recovery inventory includes exact selected old version", func(t *testing.T) {
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
			if len(v) > 0 && fmt.Sprint(v[0]) == base64.StdEncoding.EncodeToString([]byte(imported.PdfStorageKey.String)) {
				s := fmt.Sprint(v)
				found = strings.Contains(s, "draft_attachment_pdf") && strings.Contains(s, imported.PdfStorageVersionID.String)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("selected attachment absent from canonical recovery inventory")
		}
	})
	t.Run("attached legacy Send and topology changes refuse", func(t *testing.T) {
		before := packageSnapshot218(t, f, p.ID)
		_, err := f.q.BeginDocumentSendSealing(f.ctx, generated.BeginDocumentSendSealingParams{ID: root.ID, OrgID: f.org})
		packageExpectPG218(t, err, "23514")
		for _, change := range []string{"status='sent'", "is_envelope=true", "deleted_at=clock_timestamp()"} {
			_, err := f.pool.Exec(f.ctx, "UPDATE documents SET "+change+" WHERE id=$1", root.ID)
			packageExpectPG218(t, err, "23514")
		}
		if packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("unhandled package changed during refusal")
		}
	})
	t.Run("label edits generation and stale delete", func(t *testing.T) {
		old := p.DraftGeneration
		_, err := f.q.UpdateDocumentAttachmentLabelsV1(f.ctx, generated.UpdateDocumentAttachmentLabelsV1Params{PackageID: p.ID, OrgID: f.org, MemberDocumentID: imported.ID, ExpectedGeneration: old, Ordinal: 1, Title: "Data processing agreement", Category: "DPA"})
		if err != nil {
			t.Fatal(err)
		}
		p = packageFresh218(t, f, p.ID)
		if p.DraftGeneration != old+1 {
			t.Fatal("generation did not advance once")
		}
		n, err := f.q.DeleteDocumentAttachmentDraftV1(f.ctx, generated.DeleteDocumentAttachmentDraftV1Params{PackageID: p.ID, OrgID: f.org, MemberDocumentID: imported.ID, ExpectedGeneration: old})
		if err != nil || n != 0 {
			t.Fatalf("stale deletion=%d %v", n, err)
		}
	})
	t.Run("root lock serializes actual competing mutation", func(t *testing.T) {
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := f.q.WithTx(tx).LockDocumentPackageV1(f.ctx, generated.LockDocumentPackageV1Params{PackageID: p.ID, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
		other, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Rollback(context.Background())
		if _, err = other.Exec(f.ctx, "SET LOCAL lock_timeout='150ms'"); err != nil {
			t.Fatal(err)
		}
		_, err = f.q.WithTx(other).UpdateDocumentAttachmentLabelsV1(f.ctx, generated.UpdateDocumentAttachmentLabelsV1Params{PackageID: p.ID, OrgID: f.org, MemberDocumentID: imported.ID, ExpectedGeneration: p.DraftGeneration, Ordinal: 1, Title: "Should wait", Category: "DPA"})
		packageExpectPG218(t, err, "55P03")
		if err = other.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("full captured evidence and root object alias refuse", func(t *testing.T) {
		d := packagePDF218(t, f, "Captured input")
		if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET final_pdf_key='synthetic-captured-final',final_pdf_version_id='synthetic-final-version',final_pdf_sha=decode(repeat('01',32),'hex') WHERE id=$1", d.ID); err != nil {
			t.Fatal(err)
		}
		_, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, d, 3))
		packageExpectPG218(t, err, "23514")
		d, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.q.CreateDocumentPackageV1(f.ctx, generated.CreateDocumentPackageV1Params{PackageID: uuid.New(), OrgID: f.org, DocumentID: d.ID, CreatedBy: f.user.ID, ExpectedUpdatedAt: d.UpdatedAt})
		packageExpectPG218(t, err, "23514")
		alias, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Main alias", PdfStorageKey: root.PdfStorageKey, PdfSha256: root.PdfSha256, PdfStorageVersionID: root.PdfStorageVersionID, EvidenceVersionPinsRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, alias, 3))
		packageExpectPG218(t, err, "23514")
	})
	t.Run("manifest text and path shape checks agree", func(t *testing.T) {
		before := packageSnapshot218(t, f, p.ID)
		for _, label := range []string{"bad\u00a0", "bad\u2028line", "bad\u0085control"} {
			_, err := f.q.UpdateDocumentAttachmentLabelsV1(f.ctx, generated.UpdateDocumentAttachmentLabelsV1Params{PackageID: p.ID, OrgID: f.org, MemberDocumentID: imported.ID, ExpectedGeneration: p.DraftGeneration, Ordinal: 1, Title: label})
			packageExpectPG218(t, err, "23514")
		}
		var valid bool
		for _, key := range []string{imported.PdfStorageKey.String + "/../bad", imported.PdfStorageKey.String + "//bad", imported.PdfStorageKey.String + "\u00a0"} {
			if err := f.pool.QueryRow(f.ctx, "SELECT hash_package_key_v1($1,$2)", key, f.org).Scan(&valid); err != nil || valid {
				t.Fatal("unsafe package key accepted", err)
			}
		}
		if err := f.pool.QueryRow(f.ctx, "SELECT hash_package_opaque_v1($1) AND hash_package_trim_v1($1) NOT IN ('null','hash:unversioned-development')", "\u00a0null\u00a0").Scan(&valid); err != nil || valid {
			t.Fatal("reserved opaque version accepted", err)
		}
		if packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("shape refusal changed package")
		}
	})
	t.Run("sixteen member boundary and one over", func(t *testing.T) {
		for ordinal := int16(3); ordinal <= 16; ordinal++ {
			d := packagePDF218(t, f, fmt.Sprint("Annex ", ordinal))
			if _, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, d, ordinal)); err != nil {
				t.Fatal(err)
			}
			p = packageFresh218(t, f, p.ID)
		}
		count, err := f.q.CountDocumentAttachmentDraftsV1(f.ctx, generated.CountDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: f.org})
		if err != nil || count != 16 {
			t.Fatal(count, err)
		}
		before := packageSnapshot218(t, f, p.ID)
		extra := packagePDF218(t, f, "Seventeenth")
		_, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, extra, 17))
		packageExpectPG218(t, err, "23514")
		if packageSnapshot218(t, f, p.ID) != before {
			t.Fatal("one-over refusal mutated package")
		}
		members, err := f.q.ListDocumentAttachmentDraftsV1(f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: f.org, ExpectedGeneration: p.DraftGeneration})
		if err != nil || len(members) != 16 {
			t.Fatal(len(members), err)
		}
		for i, m := range members {
			if int(m.Ordinal) != i+1 {
				t.Fatal("contractual order changed")
			}
		}
	})
}

func TestDocumentAttachmentDraftPrivacyReviewV1E2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	before, err := f.q.HasHTMLAuthoringDataForDSR(f.ctx, f.org)
	if err != nil || before {
		t.Fatalf("plain tenant privacy inventory=%v %v", before, err)
	}
	root := packagePDF218(t, f, "Main privacy agreement")
	packageHeader218(t, f, root)
	held, err := f.q.HasHTMLAuthoringDataForDSR(f.ctx, f.org)
	if err != nil || !held {
		t.Fatal("package privacy inventory absent", err)
	}
	request, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	beforeState := htmlPrivacySnapshotE2E(t, f)
	w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/dsr/"+request.ID.String(), "{\"status\":\"fulfilled\"}", cookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Document attachments") {
		t.Fatalf("attachment privacy refusal=%d %s", w.Code, w.Body.String())
	}
	w = submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/data-subject/export?email="+url.QueryEscape(f.recipient.Email), "", cookie)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Document attachments") {
		t.Fatalf("attachment export refusal=%d %s", w.Code, w.Body.String())
	}
	if htmlPrivacySnapshotE2E(t, f) != beforeState {
		t.Fatal("privacy refusal changed recipients/status/events")
	}
	foreign := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	foreignHeld, err := foreign.q.HasHTMLAuthoringDataForDSR(foreign.ctx, foreign.org)
	if err != nil || foreignHeld {
		t.Fatalf("foreign package blocked other tenant: %v", err)
	}
}

func TestDocumentAttachmentDraftRollbackV1E2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	root := packagePDF218(t, f, "Rollback agreement")
	p := packageHeader218(t, f, root)
	cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	defer sqlDB.Close()
	// Empty capture migration rolls back first; preserve the occupied V99 oracle.
	if err = mdb.RunMigrationsDownToContext(f.ctx, sqlDB, 99); err != nil {
		t.Fatal(err)
	}
	if err = mdb.RunMigrationsDownContext(f.ctx, sqlDB); err == nil {
		t.Fatal("occupied package rollback erased draft work")
	}
	p = packageFresh218(t, f, p.ID)
	if _, err = f.pool.Exec(f.ctx, "UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1", root.ID); err != nil {
		t.Fatal(err)
	}
	// Exercise the V99 deletion shape while V100 is explicitly absent.
	removed, err := f.pool.Exec(f.ctx, "DELETE FROM document_packages_v1 p WHERE p.id=$1 AND p.org_id=$2 AND p.draft_generation=$3 AND NOT EXISTS(SELECT 1 FROM document_attachment_drafts_v1 a WHERE a.package_id=p.id)", p.ID, f.org, p.DraftGeneration)
	if err != nil || removed.RowsAffected() != 1 {
		t.Fatal(removed, err)
	}
	if err = mdb.RunMigrationsDownContext(f.ctx, sqlDB); err != nil {
		t.Fatal("empty rollback:", err)
	}
	if err = mdb.RunMigrationsContext(f.ctx, sqlDB); err != nil {
		t.Fatal("reapply attachment migration:", err)
	}
	var version int64
	if version, err = mdb.GetMigrationVersionContext(f.ctx, sqlDB); err != nil || version != 106 {
		t.Fatal(version, err)
	}
}
