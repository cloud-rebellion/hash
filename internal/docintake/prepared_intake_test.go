// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package docintake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type preparedIntakeQueries struct {
	*templateIntakeQueries
	reports     []generated.UpdateMetadataRedactionReportParams
	afterReport func([]byte)
}

func (q *preparedIntakeQueries) UpdateMetadataRedactionReport(ctx context.Context, p generated.UpdateMetadataRedactionReportParams) error {
	q.reports = append(q.reports, p)
	if q.afterReport != nil {
		q.afterReport(p.MetadataRedactionReport)
	}
	return q.templateIntakeQueries.UpdateMetadataRedactionReport(ctx, p)
}

type preparedIntakeStore struct {
	*templateIntakeStore
	puts      int
	beforePut func()
	forbidPut bool
}

func (s *preparedIntakeStore) PutVersioned(ctx context.Context, key, contentType string, data []byte) (storage.StoredObject, error) {
	s.puts++
	if s.forbidPut {
		return storage.StoredObject{}, errors.New("unexpected repeated storage")
	}
	if s.beforePut != nil {
		s.beforePut()
	}
	return s.templateIntakeStore.PutVersioned(ctx, key, contentType, data)
}

// These deliberately non-PDF bytes with a synthetic, internally coherent proof
// test the exact composed-result handoff only. They establish no renderer or
// worker acceptance; a second PDF parser or scrub would fail this fixture.
func preparedCompositionFixture() sanitize.PDFCompositionResult {
	raw := []byte("synthetic composition handoff bytes; no renderer acceptance")
	sum := sha256.Sum256(raw)
	output := hex.EncodeToString(sum[:])
	geometry, merged := strings.Repeat("a", 64), strings.Repeat("b", 64)
	page := sanitize.PDFPageGeometry{UserUnitMilli: 1000}
	for i := range page.BoxesMilliPoints {
		page.BoxesMilliPoints[i] = [4]int64{0, 0, 594960, 841920}
	}
	report := sanitize.Report{Asset: "synthetic-composition-handoff", ContentType: "application/pdf", Method: "pdfcpu", Stripped: []string{},
		BytesBefore: 100, BytesAfter: int64(len(raw)), Provenance: "observed", PDF: &sanitize.PDFProof{
			SchemaVersion: 1, Policy: "hash-pdf-intake-v1", SourceSHA256: merged, OutputSHA256: output,
			PagesBefore: 2, PagesAfter: 2, GeometrySHA256Before: geometry, GeometrySHA256After: geometry,
			Removed: []string{}, Absent: []string{"source_info_dictionary", "xmp_metadata", "object_streams", "linearization", "embedded_files", "acroform", "annotations"}, Generated: []string{},
		}}
	return sanitize.PDFCompositionResult{Result: sanitize.Result{Bytes: raw, Report: report}, Composition: sanitize.PDFCompositionManifest{
		SchemaVersion: 1, Policy: sanitize.PDFSigningPagePolicy, BodySHA256: strings.Repeat("c", 64), SigningPageSHA256: strings.Repeat("d", 64),
		MergedSHA256: merged, MergedBytes: report.BytesBefore, OutputSHA256: output, BodyPages: 1, FinalPages: 2,
		BodyGeometrySHA256: strings.Repeat("e", 64), GeometrySHA256: geometry, SigningPage: page,
	}}
}

func TestPreparedPDFSourceSeparatesStorageFromLockedSQLAttachment(t *testing.T) {
	org, user, template := uuid.New(), uuid.New(), uuid.New()
	locked := false
	q := &preparedIntakeQueries{templateIntakeQueries: &templateIntakeQueries{document: &generated.Document{ID: uuid.New()}}}
	q.beforeCreate = func() {
		if !locked {
			t.Fatal("SQL ran before final lock phase")
		}
	}
	st := &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}, beforePut: func() {
		if locked || len(q.createParams) != 0 || len(q.reports) != 0 {
			t.Fatal("preparation performed storage under database lock or after SQL")
		}
	}}
	prepared, err := PreparePDFTemplateSource(context.Background(), st, org, intakeTestPDF(t))
	if err != nil {
		t.Fatal(err)
	}
	if st.puts != 1 || prepared.PageCount() != 1 || len(q.createParams) != 0 || len(q.reports) != 0 {
		t.Fatal("preparation was not storage-only")
	}
	owned := prepared.OwnedSource()
	if owned.Key != st.key || owned.VersionID != st.stored.VersionID || owned.SHA256 != st.stored.SHA256 {
		t.Fatal("ownership did not come from exact put")
	}
	copy := prepared.OwnedSource()
	copy.Key, copy.VersionID, copy.SHA256[0] = "other", "other", copy.SHA256[0]^1
	if prepared.OwnedSource() != owned {
		t.Fatal("ownership accessor returned mutable state")
	}
	locked, st.forbidPut = true, true
	expires := pgtype.Timestamptz{Time: time.Date(2026, 12, 10, 0, 0, 0, 0, time.UTC), Valid: true}
	doc, err := prepared.Attach(context.Background(), q, org, user, "Prepared template", template, expires)
	if err != nil {
		t.Fatal(err)
	}
	if doc != q.document || st.puts != 1 || len(st.deletions) != 0 || len(q.createParams) != 1 || len(q.reports) != 1 {
		t.Fatal("attachment repeated storage, cleanup or skipped SQL")
	}
	p := q.createParams[0]
	if p.OrgID != org || p.SenderID != user || p.Name != "Prepared template" || p.TemplateID.Bytes != template || !p.TemplateID.Valid || p.ExpiresAt != expires ||
		p.PdfStorageKey.String != owned.Key || p.PdfStorageVersionID.String != owned.VersionID || !bytes.Equal(p.PdfSha256, owned.SHA256[:]) || !p.EvidenceVersionPinsRequired {
		t.Fatal("attachment lost exact source/actor/template pins")
	}
	if q.reports[0].ID != doc.ID || len(q.reports[0].MetadataRedactionReport) == 0 {
		t.Fatal("measured report not attached")
	}
	// Queries receive copies: even a hostile test adapter cannot change the
	// preparation later used by its owner for compensation or another check.
	p.PdfSha256[0] ^= 1
	q.reports[0].MetadataRedactionReport[0] = '!'
	if prepared.OwnedSource() != owned || !bytes.HasPrefix(prepared.report, []byte("{")) {
		t.Fatal("SQL arguments exposed private preparation state")
	}
}

func TestPreparedPDFSourceRefusesWrongOrgAndZeroIdentityBeforeSQL(t *testing.T) {
	org, user, template := uuid.New(), uuid.New(), uuid.New()
	st := &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}}
	prepared, err := PrepareComposedPDFTemplateSource(context.Background(), st, org, preparedCompositionFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"foreign_org", "missing_org", "missing_user", "missing_template", "nil_preparation", "zero_preparation", "missing_queries"} {
		t.Run(kind, func(t *testing.T) {
			p, orgID, userID, templateID := prepared, org, user, template
			q := &preparedIntakeQueries{templateIntakeQueries: &templateIntakeQueries{document: &generated.Document{ID: uuid.New()}}}
			var queries documentQueries = q
			switch kind {
			case "foreign_org":
				orgID = uuid.New()
			case "missing_org":
				orgID = uuid.Nil
			case "missing_user":
				userID = uuid.Nil
			case "missing_template":
				templateID = uuid.Nil
			case "nil_preparation":
				p = nil
			case "zero_preparation":
				p = &PreparedPDFSource{}
			case "missing_queries":
				queries = nil
			}
			doc, err := p.Attach(context.Background(), queries, orgID, userID, "Rejected", templateID, pgtype.Timestamptz{})
			if err == nil || doc != nil || len(q.createParams) != 0 || len(q.reports) != 0 || st.puts != 1 || len(st.deletions) != 0 {
				t.Fatal("invalid attachment performed effects")
			}
		})
	}
	var none *PreparedPDFSource
	if none.PageCount() != 0 || none.OwnedSource() != (OwnedPDFSource{}) {
		t.Fatal("nil preparation accessors invented ownership")
	}
}

func TestPreparedPDFSourceValidationAndStorageFailuresPerformNoSQL(t *testing.T) {
	for _, kind := range []string{"bad_pdf", "missing_org", "put_failure"} {
		t.Run(kind, func(t *testing.T) {
			org, raw := uuid.New(), []byte("not a PDF")
			putErr := errors.New("storage refused")
			st := &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}}
			if kind == "missing_org" {
				org = uuid.Nil
			}
			if kind == "put_failure" {
				raw = intakeTestPDF(t)
				st.putErr = putErr
			}
			p, err := PreparePDFTemplateSource(context.Background(), st, org, raw)
			if err == nil || p != nil || len(st.deletions) != 0 {
				t.Fatal("failed preparation published ownership or deleted an unowned write")
			}
			if kind == "put_failure" && (!errors.Is(err, putErr) || st.puts != 1) {
				t.Fatal("put failure cause lost")
			}
			if kind != "put_failure" && st.puts != 0 {
				t.Fatal("invalid PDF/identity reached storage")
			}
		})
	}
}

func TestPreparedComposedPDFSourcePreservesExactOnceCleanedBytesAndReport(t *testing.T) {
	composed := preparedCompositionFixture()
	if err := sanitize.ValidatePDFCompositionResult(composed); err != nil {
		t.Fatal("invalid test proof shape", err)
	}
	org, st := uuid.New(), &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}}
	prepared, err := PrepareComposedPDFTemplateSource(context.Background(), st, org, composed)
	if err != nil {
		t.Fatal(err)
	}
	report, err := sanitize.MergeReports(nil, composed.Report)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PageCount() != 2 || st.puts != 1 || !bytes.Equal(st.storedBytes, composed.Bytes) || !bytes.Equal(prepared.report, report) {
		t.Fatal("composed output was parsed, scrubbed or rewritten")
	}
	composed.Bytes[0] ^= 1
	composed.Report.PDF.OutputSHA256 = "changed caller proof"
	composed.Report.PDF.Absent[0] = "changed caller category"
	q := &preparedIntakeQueries{templateIntakeQueries: &templateIntakeQueries{document: &generated.Document{ID: uuid.New()}}}
	st.forbidPut = true
	if _, err := prepared.Attach(context.Background(), q, org, uuid.New(), "Composed", uuid.New(), pgtype.Timestamptz{}); err != nil {
		t.Fatal(err)
	}
	if st.puts != 1 || !bytes.Equal(q.reports[0].MetadataRedactionReport, report) || prepared.OwnedSource().SHA256 != st.stored.SHA256 {
		t.Fatal("caller mutation changed prepared proof or bytes")
	}
}

func TestPreparedComposedPDFSourceRejectsProofDriftBeforeStorage(t *testing.T) {
	for _, kind := range []string{"bytes", "report", "page_count", "geometry", "missing_org"} {
		t.Run(kind, func(t *testing.T) {
			composed, org := preparedCompositionFixture(), uuid.New()
			switch kind {
			case "bytes":
				composed.Bytes[0] ^= 1
			case "report":
				composed.Report.PDF = nil
			case "page_count":
				composed.Composition.FinalPages++
			case "geometry":
				composed.Composition.SigningPage.Rotation = 90
			case "missing_org":
				org = uuid.Nil
			}
			st := &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}}
			if prepared, err := PrepareComposedPDFTemplateSource(context.Background(), st, org, composed); err == nil || prepared != nil || st.puts != 0 || len(st.deletions) != 0 {
				t.Fatal("invalid composed proof reached storage")
			}
		})
	}
}

func TestPreparedPDFSourceChecksObservedOutputAndPageCountBeforePut(t *testing.T) {
	for _, kind := range []string{"output_digest", "output_length", "count_disagreement", "unknown_provenance", "missing_proof"} {
		t.Run(kind, func(t *testing.T) {
			cleaned, pages := preparedCompositionFixture().Result, 2
			switch kind {
			case "output_digest":
				cleaned.Report.PDF.OutputSHA256 = strings.Repeat("f", 64)
			case "output_length":
				cleaned.Report.BytesAfter++
			case "count_disagreement":
				pages++
			case "unknown_provenance":
				cleaned.Report.Provenance = "legacy-unknown"
			case "missing_proof":
				cleaned.Report.PDF = nil
			}
			st := &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}}
			if prepared, err := preparePDFSource(context.Background(), st, uuid.New(), cleaned, pages); !errors.Is(err, ErrSanitizePDF) || prepared != nil || st.puts != 0 {
				t.Fatal("clean/count/report disagreement reached storage", err)
			}
		})
	}
}

func TestPreparedPDFSourceAttachmentFailureRetainsCallerOwnedObject(t *testing.T) {
	for _, kind := range []string{"insert", "report", "missing_result"} {
		t.Run(kind, func(t *testing.T) {
			org, st := uuid.New(), &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}}
			prepared, err := PrepareComposedPDFTemplateSource(context.Background(), st, org, preparedCompositionFixture())
			if err != nil {
				t.Fatal(err)
			}
			owned := prepared.OwnedSource()
			dbErr := errors.New("attachment SQL failure")
			q := &preparedIntakeQueries{templateIntakeQueries: &templateIntakeQueries{document: &generated.Document{ID: uuid.New()}}}
			switch kind {
			case "insert":
				q.createErr = dbErr
			case "report":
				q.reportErr = dbErr
			case "missing_result":
				q.document = nil
			}
			doc, err := prepared.Attach(context.Background(), q, org, uuid.New(), "Failure", uuid.New(), pgtype.Timestamptz{})
			if err == nil || doc != nil || len(st.deletions) != 0 || prepared.OwnedSource() != owned {
				t.Fatal("attachment deleted or discarded caller cleanup ownership")
			}
			if kind != "missing_result" && !errors.Is(err, dbErr) {
				t.Fatal("database failure lost its cause")
			}
		})
	}
}

func TestPreparedIntakeLegacyWrappersPreserveTemplatelessAndSingleCompensation(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	q := &preparedIntakeQueries{templateIntakeQueries: &templateIntakeQueries{document: &generated.Document{ID: uuid.New()}}}
	st := &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{}}
	if _, pages, err := CreatePDFSourceDocument(context.Background(), q, st, org, user, "Legacy static", intakeTestPDF(t)); err != nil || pages != 1 {
		t.Fatal(err)
	}
	if q.createParams[0].TemplateID.Valid || q.createParams[0].ExpiresAt.Valid || st.puts != 1 || len(st.deletions) != 0 {
		t.Fatal("template-less wrapper behavior changed")
	}
	for _, kind := range []string{"insert", "report"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dbErr, cleanupErr := errors.New("legacy SQL failure"), errors.New("legacy cleanup failure")
			q := &preparedIntakeQueries{templateIntakeQueries: &templateIntakeQueries{document: &generated.Document{ID: uuid.New()}, beforeCreate: cancel}}
			if kind == "insert" {
				q.createErr = dbErr
			} else {
				q.reportErr = dbErr
			}
			st := &preparedIntakeStore{templateIntakeStore: &templateIntakeStore{deleteErr: cleanupErr}}
			doc, pages, owned, err := CreateComposedPDFTemplateDocument(ctx, q, st, org, user, "Failure", uuid.New(), pgtype.Timestamptz{}, preparedCompositionFixture())
			if !errors.Is(err, dbErr) || !errors.Is(err, cleanupErr) || doc != nil || pages != 0 || owned != (OwnedPDFSource{}) || st.puts != 1 || len(st.deletions) != 1 {
				t.Fatal("legacy wrapper lost error or cleaned twice", err)
			}
			want := OwnedPDFSource{Key: st.key, VersionID: st.stored.VersionID, SHA256: st.stored.SHA256}
			if st.deletions[0] != want || st.deleteCtxErr != nil || !st.deleteHasDeadline {
				t.Fatal("legacy compensation was not exact, detached and bounded")
			}
		})
	}
}
