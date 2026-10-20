// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlmaterialization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are pure semantic oracles, using the existing genuine canonical-source
// fixture and unchanged Current/RegisterOrigin helpers. The in-memory queries
// assert no PostgreSQL, native work, PDF measurement or human-review authority.
func TestPreparedCurrentKeepsOriginalTupleAndReportRefusalsV1(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.HtmlDocumentMaterialization)
	}{
		{"identity", func(r *generated.HtmlDocumentMaterialization) { r.ID = uuid.New() }},
		{"document", func(r *generated.HtmlDocumentMaterialization) { r.DocumentID = uuid.New() }},
		{"organisation", func(r *generated.HtmlDocumentMaterialization) { r.OrgID = uuid.New() }},
		{"sequence", func(r *generated.HtmlDocumentMaterialization) { r.Sequence++ }},
		{"pages", func(r *generated.HtmlDocumentMaterialization) { r.PageCount++ }},
		{"PDF key", func(r *generated.HtmlDocumentMaterialization) { r.PdfKey += "/other" }},
		{"PDF version", func(r *generated.HtmlDocumentMaterialization) { r.PdfVersionID += "-other" }},
		{"PDF hash", func(r *generated.HtmlDocumentMaterialization) { r.PdfSha256 = bytes.Repeat([]byte{9}, 32) }},
		{"source commitment", func(r *generated.HtmlDocumentMaterialization) { r.SourceCommitment = bytes.Repeat([]byte{8}, 32) }},
		{"origin commitment", func(r *generated.HtmlDocumentMaterialization) { r.OriginCommitment = bytes.Repeat([]byte{7}, 32) }},
		{"report projection", func(r *generated.HtmlDocumentMaterialization) { r.MetadataRedactionReport = []byte("{}") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, q := fixture(t)
			q.doc.MetadataRedactionReport = observedEnvelope(t, q.doc.PdfSha256, 1)
			doc, row, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
			if err != nil {
				t.Fatal(err)
			}
			v, err := htmlsource.NewRevisionValidationV1(doc)
			if err != nil {
				t.Fatal(err)
			}
			if required, err := ValidateCurrentReadProjectionMetadataPreparedV1(doc, currentReadProjectionV1(row), v); err != nil || !required {
				t.Fatal("exact original metadata refused", required, err)
			}
			changed := *row
			tc.mutate(&changed)
			q.rows[row.ID] = &changed
			if got, err := Current(context.Background(), q, doc); got != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("original Current did not refuse the oracle drift", got, err)
			}
			if required, err := ValidateCurrentReadProjectionMetadataPreparedV1(doc, currentReadProjectionV1(&changed), v); required || !errors.Is(err, ErrInvalid) {
				t.Fatal("prepared prefix omitted an original tuple/report check", required, err)
			}
			// A malformed row source does not displace the original earlier tuple/report
			// refusal: no row-source validation operation is needed for this decision.
			changed.SourceJson = []byte("{")
			if required, err := ValidateCurrentReadProjectionMetadataPreparedV1(doc, currentReadProjectionV1(&changed), v); required || !errors.Is(err, ErrInvalid) {
				t.Fatal("row transport changed metadata refusal ordering", required, err)
			}
			if err := ValidateCurrentReadProjectionPreparedV1(doc, currentReadProjectionV1(&changed), v, nil); !errors.Is(err, ErrInvalid) {
				t.Fatal("unvalidated row source displaced metadata refusal", err)
			}
		})
	}
}

func TestPreparedCurrentRequiresRealTransportValidationAndCompleteDocumentPinsV1(t *testing.T) {
	_, q := fixture(t)
	doc, row, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	v, err := htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateCurrentReadProjectionPreparedV1(doc, currentReadProjectionV1(row), v, v); err != nil {
		t.Fatal("exact already-validated transport refused", err)
	}
	var pretty bytes.Buffer
	if err = json.Indent(&pretty, row.SourceJson, "", "  "); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pretty.Bytes(), row.SourceJson) {
		t.Fatal("fixture did not produce distinct source transport")
	}
	transported := *row
	transported.SourceJson = bytes.Clone(pretty.Bytes())
	q.rows[row.ID] = &transported
	if _, err = Current(context.Background(), q, doc); err != nil {
		t.Fatal("original Current refused semantically identical transport", err)
	}
	projection := currentReadProjectionV1(&transported)
	if required, err := ValidateCurrentReadProjectionMetadataPreparedV1(doc, projection, v); err != nil || !required {
		t.Fatal("metadata preflight parsed or rejected row transport", required, err)
	}
	if err = ValidateCurrentReadProjectionPreparedV1(doc, projection, v, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("claimed row commitment substituted missing full row validation", err)
	}
	if err = ValidateCurrentReadProjectionPreparedV1(doc, projection, v, v); !errors.Is(err, ErrInvalid) {
		t.Fatal("original transport operation was reused for changed row bytes", err)
	}
	actual := *doc
	actual.HtmlCurrentSourceJson = transported.SourceJson
	rowV, err := htmlsource.NewRevisionValidationV1(&actual)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateCurrentReadProjectionPreparedV1(doc, projection, v, rowV); err != nil {
		t.Fatal("genuine distinct row transport validation refused", err)
	}
	changedDoc := *doc
	changedDoc.Name = "mutated caller document pin"
	if err = ValidateCurrentReadProjectionPreparedV1(&changedDoc, projection, v, rowV); !errors.Is(err, htmlsource.ErrInvalid) {
		t.Fatal("complete document mutation reused old immutable validation", err)
	}
	broken := *row
	broken.SourceJson = []byte("{")
	q.rows[row.ID] = &broken
	if got, err := Current(context.Background(), q, doc); err == nil || got != nil {
		t.Fatal("original Current accepted corrupt row source")
	}
	corrupt := *doc
	corrupt.HtmlCurrentSourceJson = broken.SourceJson
	if _, err = htmlsource.NewRevisionValidationV1(&corrupt); err == nil {
		t.Fatal("row's unchanged digest granted validation of corrupt source")
	}
	if err = ValidateCurrentReadProjectionPreparedV1(doc, currentReadProjectionV1(&broken), v, rowV); !errors.Is(err, ErrInvalid) {
		t.Fatal("a different valid transport operation validated corrupt row bytes", err)
	}
}

func TestPreparedCurrentKeepsLegacyAndNullableReportBehaviorV1(t *testing.T) {
	_, q := fixture(t)
	v, err := htmlsource.NewRevisionValidationV1(q.doc)
	if err != nil {
		t.Fatal(err)
	}
	if row, err := Current(context.Background(), nil, q.doc); row != nil || err != nil {
		t.Fatal("original legacy behavior changed", row, err)
	}
	if required, err := ValidateCurrentReadProjectionMetadataPreparedV1(q.doc, nil, v); required || err != nil {
		t.Fatal("legacy acquired a normalized row requirement", required, err)
	}
	if err = ValidateCurrentReadProjectionPreparedV1(q.doc, nil, v, nil); err != nil {
		t.Fatal("legacy required row-source validation", err)
	}
	if err = ValidateCurrentReadProjectionPreparedV1(q.doc, &CurrentReadProjectionV1{ID: uuid.New()}, v, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("orphan projection became legacy authority", err)
	}
	doc, row, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// Original pre-report rows may be NULL even when the document has a later
	// observed envelope. This never converts NULL into measured provenance.
	row.MetadataRedactionReport = nil
	doc.MetadataRedactionReport = observedEnvelope(t, doc.PdfSha256, 1)
	v, err = htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Current(context.Background(), q, doc); err != nil {
		t.Fatal("original NULL row behavior changed", err)
	}
	if err = ValidateCurrentReadProjectionPreparedV1(doc, currentReadProjectionV1(row), v, v); err != nil {
		t.Fatal("prepared read invented a legacy report", err)
	}
	// Matching malformed report bytes must still reach the unchanged real report
	// validator. Raw equality alone is not sanitation provenance.
	row.MetadataRedactionReport = []byte("{")
	doc.MetadataRedactionReport = bytes.Clone(row.MetadataRedactionReport)
	v, err = htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Current(context.Background(), q, doc); !errors.Is(err, ErrInvalid) {
		t.Fatal("original malformed report oracle changed", err)
	}
	if required, err := ValidateCurrentReadProjectionMetadataPreparedV1(doc, currentReadProjectionV1(row), v); required || !errors.Is(err, ErrInvalid) {
		t.Fatal("matching malformed report bypassed original report validation", required, err)
	}
}

func TestPreparedLegacyOriginPrefixKeepsOriginalPrewriteOrderingV1(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Document, *int32, *uuid.UUID)
	}{
		{"nil actor", func(_ *generated.Document, _ *int32, a *uuid.UUID) { *a = uuid.Nil }},
		{"no pages", func(_ *generated.Document, p *int32, _ *uuid.UUID) { *p = 0 }},
		{"too many pages", func(_ *generated.Document, p *int32, _ *uuid.UUID) { *p = 501 }},
		{"non draft", func(d *generated.Document, _ *int32, _ *uuid.UUID) { d.Status = "changes_requested" }},
		{"missing CAS", func(d *generated.Document, _ *int32, _ *uuid.UUID) { d.UpdatedAt = pgtype.Timestamptz{} }},
		{"malformed report", func(d *generated.Document, _ *int32, _ *uuid.UUID) { d.MetadataRedactionReport = []byte("{") }},
		{"wrong measured PDF", func(d *generated.Document, _ *int32, _ *uuid.UUID) {
			d.MetadataRedactionReport = observedEnvelope(t, bytes.Repeat([]byte{9}, 32), 1)
		}},
		{"wrong measured pages", func(d *generated.Document, _ *int32, _ *uuid.UUID) {
			d.MetadataRedactionReport = observedEnvelope(t, d.PdfSha256, 2)
		}},
	}
	if err := PrepareOriginValidationV1(nil, 1, uuid.New()); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil legacy parent accepted", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, q := fixture(t)
			pages, actor := int32(1), uuid.New()
			tc.mutate(q.doc, &pages, &actor)
			// Corrupt source creates a distinguishable later htmlsource failure. Every
			// original legacy prefix refusal must win before source parse or any write.
			q.doc.HtmlSourceJson = []byte("{")
			_, _, original := RegisterOrigin(context.Background(), q, q.doc, pages, actor)
			prepared := PrepareOriginValidationV1(q.doc, pages, actor)
			if !errors.Is(original, ErrInvalid) || !errors.Is(prepared, ErrInvalid) || q.writes != 0 {
				t.Fatal("legacy prewrite order/effects changed", original, prepared, q.writes)
			}
		})
	}
	for _, report := range []string{"", "{}"} {
		t.Run("accepted legacy report "+report, func(t *testing.T) {
			_, q := fixture(t)
			q.doc.MetadataRedactionReport = []byte(report)
			if err := PrepareOriginValidationV1(q.doc, 1, uuid.New()); err != nil || q.writes != 0 {
				t.Fatal("pure prefix wrote history or refused valid legacy report", err, q.writes)
			}
			if _, _, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New()); err != nil || q.writes != 2 {
				t.Fatal("original legacy producer behavior changed", err, q.writes)
			}
		})
	}
	_, q := fixture(t)
	q.doc.HtmlSourceJson = []byte("{")
	if err := PrepareOriginValidationV1(q.doc, 1, uuid.New()); err != nil {
		t.Fatal("prefix improperly claimed source validation", err)
	}
	if _, _, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New()); !errors.Is(err, htmlsource.ErrInvalid) || q.writes != 0 {
		t.Fatal("pure prefix bypassed later original source validation", err, q.writes)
	}
}
