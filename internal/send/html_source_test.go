// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

func reviewedHTMLDocument(t *testing.T) *generated.Document {
	t.Helper()
	master, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1, HTML: `<p>Customer <span data-hash-value="customer_name"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer_name", Required: true, MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Approved work", MaxChars: 500}},
	})
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := htmlmaster.CanonicalTemplate(master, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	templateID := uuid.New()
	sum := sha256.Sum256([]byte("synthetic HTML source guard fixture; not actual rendering evidence"))
	approval := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), SourceKind: "pdf", Status: "draft", RequiresSignature: true,
		TemplateID: pgtype.UUID{Bytes: templateID, Valid: true}, VariablesJson: []byte(`{"customer_name":"Reviewed AB"}`),
		PdfStorageKey: pgtype.Text{String: "org/guard/document/source.pdf", Valid: true}, PdfSha256: sum[:],
		PdfStorageVersionID: pgtype.Text{String: "source-version-1", Valid: true}, EvidenceVersionPinsRequired: true,
		HtmlReviewedPdfSha256: bytes.Clone(sum[:]), HtmlReviewedBy: pgtype.UUID{Bytes: uuid.New(), Valid: true},
		HtmlReviewedAt: pgtype.Timestamptz{Time: approval.Add(time.Hour), Valid: true},
	}
	doc.HtmlSourceJson, err = htmlsource.New(htmlsource.Input{TemplateID: templateID, TemplateVersion: 3, TemplateContentSHA256: commitment.SHA256,
		MasterJSON: commitment.MasterJSON, DefaultVarsJSON: commitment.DefaultsJSON, Values: map[string]string{"customer_name": "Reviewed AB"},
		TemplateApprovedBy: uuid.New(), TemplateApprovedAt: approval,
	}, doc)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestHTMLSourceSendAndSealingRejectUnreviewedOrStalePrintedValues(t *testing.T) {
	for _, path := range []string{"prepare", "recovered sealing", "envelope child"} {
		t.Run(path, func(t *testing.T) {
			for _, state := range []string{"reviewed", "unreviewed", "CRM changed", "source changed"} {
				t.Run(state, func(t *testing.T) {
					doc := reviewedHTMLDocument(t)
					var want error
					switch state {
					case "unreviewed":
						doc.HtmlReviewedAt.Valid = false
						want = htmlsource.ErrReviewRequired
					case "CRM changed":
						doc.VariablesJson = []byte(`{"customer_name":"New CRM value"}`)
						want = htmlsource.ErrInvalid
					case "source changed":
						doc.PdfStorageVersionID.String = "different-source-version"
						want = htmlsource.ErrInvalid
					}
					var err error
					switch path {
					case "prepare":
						err = validateResolvedBlockVariables(doc)
					case "recovered sealing":
						doc.Status = "sealing"
						err = validateResolvedSealedSnapshot(doc, nil)
					case "envelope child":
						err = validateResolvedSealedSnapshot(&generated.Document{SourceKind: "pdf"}, []*generated.Document{doc})
					}
					if want == nil && err != nil {
						t.Fatal(err)
					}
					if want != nil && !errors.Is(err, want) {
						t.Fatalf("error = %v; want %v", err, want)
					}
				})
			}
		})
	}
}

func TestHTMLSourceFrozenCRMValuesRefusedBeforeDatabaseWrite(t *testing.T) {
	doc := reviewedHTMLDocument(t)
	// Nil queries intentionally prove refusal happens before the write boundary.
	_, err := persistAuthorizedFrozenDocument(context.Background(), nil, doc, []byte(`{"customer_name":"Changed after preview"}`))
	if !errors.Is(err, htmlsource.ErrInvalid) {
		t.Fatalf("freeze = %v", err)
	}
	if string(doc.VariablesJson) != `{"customer_name":"Reviewed AB"}` {
		t.Fatal("validation mutated persisted draft")
	}
}

func TestHTMLSourceRetentionRejectsInvalidSnapshotBeforeStorageEffects(t *testing.T) {
	for _, state := range []string{"reviewed", "unreviewed", "stale values", "missing source version"} {
		t.Run(state, func(t *testing.T) {
			doc := reviewedHTMLDocument(t)
			var want error
			switch state {
			case "unreviewed":
				doc.HtmlReviewedBy.Valid = false
				want = htmlsource.ErrReviewRequired
			case "stale values":
				doc.VariablesJson = []byte(`{"customer_name":"Changed"}`)
				want = htmlsource.ErrInvalid
			case "missing source version":
				doc.PdfStorageVersionID.Valid = false
				want = htmlsource.ErrInvalid
			}
			retainer := &fakeEvidenceRetainer{}
			err := retainSendEvidence(context.Background(), retainer, doc, time.Now().Add(24*time.Hour))
			if want == nil {
				if err != nil || len(retainer.calls) != 1 {
					t.Fatalf("reviewed retention = %v; calls %v", err, retainer.calls)
				}
			} else {
				if !errors.Is(err, want) || len(retainer.calls) != 0 {
					t.Fatalf("invalid retention = %v; calls %v", err, retainer.calls)
				}
				if _, err := inspectSendSourcePDF(context.Background(), nil, doc); !errors.Is(err, want) {
					t.Fatalf("source read did not refuse before storage: %v", err)
				}
			}
		})
	}
}

func TestHTMLSourceLockWaitComparisonIncludesProvenanceAndReview(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"provenance", func(d *generated.Document) { d.HtmlSourceJson = []byte(`{}`) }},
		{"review hash", func(d *generated.Document) { d.HtmlReviewedPdfSha256 = bytes.Repeat([]byte{3}, 32) }},
		{"review actor", func(d *generated.Document) { d.HtmlReviewedBy.Bytes = uuid.New() }},
		{"review timestamp", func(d *generated.Document) { d.HtmlReviewedAt.Time = d.HtmlReviewedAt.Time.Add(time.Second) }},
		{"review withdrawn", func(d *generated.Document) { d.HtmlReviewedAt.Valid = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared := reviewedHTMLDocument(t)
			locked := *prepared
			tc.mutate(&locked)
			if err := verifyPreparedSendDocument(prepared, &locked); !errors.Is(err, ErrDraftChangedDuringSend) {
				t.Fatalf("initial lock wait = %v", err)
			}
			if err := verifyPreparedSealedDocument(prepared, &locked); !errors.Is(err, ErrDraftChangedDuringSend) {
				t.Fatalf("terminal lock wait = %v", err)
			}
		})
	}
}

// A reviewed HTML PDF already commits its complete current values. A valid
// same-value resolver result must not rewrite that actual stored snapshot just
// because PostgreSQL JSONB and encoding/json spell it differently. Nil queries
// prove the no-write boundary; actual cache survival is qualified in the public
// owned-PG lifecycle, not fabricated by this source fixture.
func TestReviewedHTMLSameValuesRetainOriginalSnapshotWithoutSQL(t *testing.T) {
	for _, spelling := range []string{"{\"customer_name\":\"Reviewed AB\"}", "{\n  \"customer_name\": \"Reviewed AB\"\n}", "{\"customer_name\":\"Reviewed \\u0041B\"}"} {
		t.Run(spelling, func(t *testing.T) {
			doc := reviewedHTMLDocument(t)
			doc.VariablesJson = json.RawMessage("{ \"customer_name\" : \"Reviewed AB\" }")
			doc.UpdatedAt = pgtype.Timestamptz{Time: time.Date(2026, 10, 14, 10, 0, 0, 123000, time.UTC), Valid: true}
			before := *doc
			before.VariablesJson = bytes.Clone(doc.VariablesJson)
			before.HtmlSourceJson = bytes.Clone(doc.HtmlSourceJson)
			before.PdfSha256 = bytes.Clone(doc.PdfSha256)
			before.HtmlReviewedPdfSha256 = bytes.Clone(doc.HtmlReviewedPdfSha256)
			got, err := persistAuthorizedFrozenDocument(context.Background(), nil, doc, json.RawMessage(spelling))
			if err != nil || got != doc || !reflect.DeepEqual(doc, &before) {
				t.Fatalf("same-value HTML snapshot was rewritten: same_original=%t unchanged=%t error=%v", got == doc, reflect.DeepEqual(doc, &before), err)
			}
		})
	}
}

func TestReviewedHTMLNoWriteCannotRepairInvalidOriginalOrAcceptChangedValues(t *testing.T) {
	for _, state := range []string{"changed resolved value", "extra resolved value", "invalid original values", "review missing"} {
		t.Run(state, func(t *testing.T) {
			doc := reviewedHTMLDocument(t)
			frozen := json.RawMessage(`{"customer_name":"Reviewed AB"}`)
			want := htmlsource.ErrInvalid
			switch state {
			case "changed resolved value":
				frozen = json.RawMessage(`{"customer_name":"Changed after preview"}`)
			case "extra resolved value":
				frozen = json.RawMessage(`{"customer_name":"Reviewed AB","unreviewed":"extra"}`)
			case "invalid original values":
				doc.VariablesJson = json.RawMessage(`{"customer_name":"Original differs from reviewed PDF"}`)
			case "review missing":
				doc.HtmlReviewedBy.Valid = false
				want = htmlsource.ErrReviewRequired
			}
			before := bytes.Clone(doc.VariablesJson)
			got, err := persistAuthorizedFrozenDocument(context.Background(), nil, doc, frozen)
			if got != nil || !errors.Is(err, want) || !bytes.Equal(before, doc.VariablesJson) {
				t.Fatalf("invalid snapshot passed no-write gate: returned=%t unchanged=%t error=%v want=%v", got != nil, bytes.Equal(before, doc.VariablesJson), err, want)
			}
		})
	}
}

func TestReviewedHTMLSameValuesNoWriteHonorsOriginalContext(t *testing.T) {
	doc := reviewedHTMLDocument(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := bytes.Clone(doc.VariablesJson)
	got, err := persistAuthorizedFrozenDocument(ctx, nil, doc, json.RawMessage(`{"customer_name":"Reviewed AB"}`))
	if got != nil || !errors.Is(err, context.Canceled) || !bytes.Equal(before, doc.VariablesJson) {
		t.Fatalf("cancelled no-write accepted: returned=%t unchanged=%t error=%v", got != nil, bytes.Equal(before, doc.VariablesJson), err)
	}
}
