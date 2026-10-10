// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

type memoryQueries struct {
	doc      *generated.Document
	rows     map[uuid.UUID]*generated.HtmlDocumentMaterialization
	captures []*generated.Document
	writes   int
	cleared  bool
	corrupt  bool
}

func (q *memoryQueries) GetCurrentHTMLDocumentMaterialization(context.Context, generated.GetCurrentHTMLDocumentMaterializationParams) (*generated.HtmlDocumentMaterialization, error) {
	row := *q.rows[uuid.UUID(q.doc.HtmlCurrentMaterializationID.Bytes)]
	if q.corrupt {
		row.PdfVersionID = "wrong-version"
	}
	return &row, nil
}
func (q *memoryQueries) InsertHTMLDocumentMaterialization(_ context.Context, p generated.InsertHTMLDocumentMaterializationParams) (*generated.HtmlDocumentMaterialization, error) {
	q.writes++
	row := &generated.HtmlDocumentMaterialization{ID: uuid.New(), DocumentID: p.DocumentID, OrgID: p.OrgID, Sequence: p.Sequence, ParentID: p.ParentID, ParentCommitment: p.ParentCommitment, OriginCommitment: p.OriginCommitment, SourceJson: p.SourceJson, SourceCommitment: p.SourceCommitment, PdfKey: p.PdfKey, PdfSha256: p.PdfSha256, PdfVersionID: p.PdfVersionID, PageCount: p.PageCount}
	row.MetadataRedactionReport = bytes.Clone(p.MetadataRedactionReport)
	q.rows[row.ID] = row
	return row, nil
}
func (q *memoryQueries) ProjectHTMLDocumentMaterialization(_ context.Context, p generated.ProjectHTMLDocumentMaterializationParams) (*generated.Document, error) {
	q.writes++
	row := q.rows[p.MaterializationID]
	doc := *q.doc
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: row.ID, Valid: true}
	doc.HtmlCurrentSourceJson = bytes.Clone(row.SourceJson)
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: row.PageCount, Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: row.Sequence, Valid: true}
	doc.PdfStorageKey = pgtype.Text{String: row.PdfKey, Valid: true}
	doc.PdfSha256 = bytes.Clone(row.PdfSha256)
	doc.PdfStorageVersionID = pgtype.Text{String: row.PdfVersionID, Valid: true}
	doc.MetadataRedactionReport = bytes.Clone(row.MetadataRedactionReport)
	if len(doc.MetadataRedactionReport) == 0 {
		doc.MetadataRedactionReport = json.RawMessage(`{}`)
	}
	var s struct {
		Values json.RawMessage `json:"values"`
	}
	_ = json.Unmarshal(row.SourceJson, &s)
	doc.VariablesJson = s.Values
	if row.Sequence > 1 {
		doc.HtmlReviewedBy = pgtype.UUID{}
		doc.HtmlReviewedAt = pgtype.Timestamptz{}
		doc.HtmlReviewedPdfSha256 = nil
		doc.HtmlReviewedMaterializationID = pgtype.UUID{}
	} else if doc.HtmlReviewedBy.Valid {
		doc.HtmlReviewedMaterializationID = doc.HtmlCurrentMaterializationID
	}
	doc.UpdatedAt = pgtype.Timestamptz{Time: doc.UpdatedAt.Time.Add(time.Microsecond), Valid: true}
	q.doc = &doc
	return &doc, nil
}
func (q *memoryQueries) CaptureHTMLMaterializationSnapshot(_ context.Context, p generated.CaptureHTMLMaterializationSnapshotParams) (*generated.HtmlDocumentMaterializationSnapshot, error) {
	q.writes++
	d := *q.doc
	q.captures = append(q.captures, &d)
	return &generated.HtmlDocumentMaterializationSnapshot{}, nil
}
func (q *memoryQueries) ClearUnsignedHTMLMaterializationFields(context.Context, generated.ClearUnsignedHTMLMaterializationFieldsParams) (int64, error) {
	q.writes++
	q.cleared = true
	return 2, nil
}

func fixture(t *testing.T) (htmlsource.Input, *memoryQueries) {
	t.Helper()
	m, _ := json.Marshal(htmlmaster.Master{SchemaVersion: 1, HTML: `<p><span data-hash-value="customer"></span></p><div data-hash-section="scope"></div>`, Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 100}}, Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Original prose", MaxChars: 200}}})
	c, err := htmlmaster.CanonicalTemplate(m, []byte(`{"customer":"Default AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	in := htmlsource.Input{TemplateID: uuid.New(), TemplateVersion: 2, TemplateContentSHA256: c.SHA256, MasterJSON: c.MasterJSON, DefaultVarsJSON: c.DefaultsJSON, Values: map[string]string{"customer": "First AB"}, Sections: map[string]string{}, TemplateApprovedBy: uuid.New(), TemplateApprovedAt: time.Now().Add(-time.Hour)}
	sum := sha256.Sum256([]byte("synthetic fixed PDF; no render equivalence claim"))
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), TemplateID: pgtype.UUID{Bytes: in.TemplateID, Valid: true}, SourceKind: "pdf", Status: "draft", PdfStorageKey: pgtype.Text{String: "org/test/documents/source.pdf", Valid: true}, PdfSha256: sum[:], PdfStorageVersionID: pgtype.Text{String: "version-one", Valid: true}, VariablesJson: []byte(`{"customer":"First AB"}`), UpdatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}, EvidenceVersionPinsRequired: true}
	doc.HtmlSourceJson, err = htmlsource.New(in, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlReviewedBy = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlReviewedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	doc.HtmlReviewedPdfSha256 = bytes.Clone(doc.PdfSha256)
	return in, &memoryQueries{doc: doc, rows: map[uuid.UUID]*generated.HtmlDocumentMaterialization{}}
}

func TestHTMLMaterializationSamePDFRevisionRetainsOriginAndRequiresFreshReview(t *testing.T) {
	in, q := fixture(t)
	original := bytes.Clone(q.doc.HtmlSourceJson)
	old := q.doc
	candidate := *old
	in.Values["customer"] = "Negotiated AB"
	candidate.VariablesJson, _ = json.Marshal(in.Values)
	candidate.PdfStorageKey.String = "org/test/documents/new.pdf"
	candidate.PdfStorageVersionID.String = "version-two"
	raw, err := htmlsource.New(in, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	updated, row, err := Append(context.Background(), q, old, &candidate, AppendInput{SourceJSON: raw, PageCount: 2, PreviousPageCount: 1, ActorID: uuid.New(), Summary: "Reviewed negotiated information"})
	if err != nil {
		t.Fatal(err)
	}
	if row.Sequence != 2 || !bytes.Equal(updated.HtmlSourceJson, original) || !bytes.Equal(updated.PdfSha256, old.PdfSha256) || !q.cleared || len(q.captures) != 1 || !q.captures[0].HtmlReviewedBy.Valid {
		t.Fatal("origin/artifact/review/layout history contract lost")
	}
	if !errors.Is(htmlsource.Validate(updated, true), htmlsource.ErrReviewRequired) {
		t.Fatal("identical PDF inherited old review")
	}
	origin, _ := htmlsource.OriginCommitment(updated)
	if hex.EncodeToString(row.OriginCommitment) != origin {
		t.Fatal("chain anchor changed")
	}
}

func TestHTMLMaterializationRejectsDriftBeforeHistoryEffects(t *testing.T) {
	for _, kind := range []string{"PDFversion", "templateapproval", "unchangedcontent", "summary"} {
		t.Run(kind, func(t *testing.T) {
			in, q := fixture(t)
			candidate := *q.doc
			in.Values["customer"] = "Second AB"
			candidate.VariablesJson, _ = json.Marshal(in.Values)
			if kind == "unchangedcontent" {
				in.Values["customer"] = "First AB"
				candidate.VariablesJson = []byte(`{"customer":"First AB"}`)
			}
			if kind == "templateapproval" {
				in.TemplateApprovedBy = uuid.New()
			}
			raw, err := htmlsource.New(in, &candidate)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "PDFversion" {
				candidate.PdfStorageVersionID.String = "changed-after-source"
			}
			summary := "revision"
			if kind == "summary" {
				summary = "bad\x00summary"
			}
			_, _, err = Append(context.Background(), q, q.doc, &candidate, AppendInput{SourceJSON: raw, PageCount: 1, PreviousPageCount: 1, ActorID: uuid.New(), Summary: summary})
			if err == nil || q.writes != 0 {
				t.Fatalf("drift accepted or wrote history: error=%v writes=%d", err, q.writes)
			}
		})
	}
	in, q := fixture(t)
	doc, _, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	q.corrupt = true
	q.writes = 0
	candidate := *doc
	in.Values["customer"] = "Second AB"
	candidate.VariablesJson, _ = json.Marshal(in.Values)
	raw, _ := htmlsource.New(in, &candidate)
	if _, _, err := Append(context.Background(), q, doc, &candidate, AppendInput{SourceJSON: raw, PageCount: 1, ActorID: uuid.New()}); err == nil || q.writes != 0 {
		t.Fatal("wrong normalized version accepted before writes")
	}
}

func TestHTMLMaterializationHistoryValidatesExactPinsWithoutCurrentReview(t *testing.T) {
	_, q := fixture(t)
	doc, row, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	view, err := HistoricalDocument(doc, row)
	if err != nil {
		t.Fatal(err)
	}
	if view.HtmlReviewedBy.Valid || !errors.Is(htmlsource.Validate(view, true), htmlsource.ErrReviewRequired) {
		t.Fatal("historical read carried current approval authority")
	}
	for _, mutate := range []func(*generated.HtmlDocumentMaterialization){
		func(r *generated.HtmlDocumentMaterialization) { r.PdfVersionID = "foreign-version" },
		func(r *generated.HtmlDocumentMaterialization) { r.DocumentID = uuid.New() },
		func(r *generated.HtmlDocumentMaterialization) { r.SourceCommitment = bytes.Repeat([]byte{9}, 32) },
		func(r *generated.HtmlDocumentMaterialization) { r.OriginCommitment = bytes.Repeat([]byte{9}, 32) },
	} {
		copy := *row
		mutate(&copy)
		if _, err := HistoricalDocument(doc, &copy); err == nil {
			t.Fatal("foreign or drifted history row accepted")
		}
	}
}
