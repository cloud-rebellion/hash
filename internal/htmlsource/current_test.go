// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
)

func currentFixture(t *testing.T) (Input, *generated.Document) {
	t.Helper()
	input, doc := sourceFixture(t)
	attachSource(t, input, doc)
	original := bytes.Clone(doc.HtmlSourceJson)
	input.Values["customer_name"] = "Negotiated AB"
	input.Sections["scope"] = "New reviewed scope"
	doc.VariablesJson, _ = json.Marshal(input.Values)
	doc.PdfStorageKey.String = "org/example/documents/revision.pdf"
	doc.PdfStorageVersionID.String = "opaque-version-2"
	current, err := New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson = original
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlCurrentSourceJson = current
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
	return input, doc
}

func TestHTMLSourceCurrentProjectionPreservesOriginAndFrozenInputs(t *testing.T) {
	input, doc := currentFixture(t)
	origin := bytes.Clone(doc.HtmlSourceJson)
	if err := Validate(doc, false); err != nil {
		t.Fatal(err)
	}
	current, err := Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := OriginCommitment(doc)
	if err != nil || current == anchor {
		t.Fatal("current/source chain anchors were conflated")
	}
	recovered, err := InputForCurrent(doc)
	if err != nil || recovered.Values["customer_name"] != "Negotiated AB" || recovered.Sections["scope"] != "New reviewed scope" || recovered.TemplateVersion != input.TemplateVersion {
		t.Fatal("current inputs or frozen template lost")
	}
	recovered.Values["customer_name"] = "mutated copy"
	recovered.MasterJSON[0] = 'x'
	raw, err := EffectiveJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'x'
	if err := Validate(doc, false); err != nil || !bytes.Equal(doc.HtmlSourceJson, origin) {
		t.Fatal("accessor rewrote source")
	}
	approveFixture(doc, input)
	if !errors.Is(Validate(doc, true), ErrReviewRequired) {
		t.Fatal("old same-digest review inherited by new materialization")
	}
	doc.HtmlReviewedMaterializationID = doc.HtmlCurrentMaterializationID
	if err := Validate(doc, true); err != nil {
		t.Fatal(err)
	}
}

func TestHTMLSourceCurrentProjectionNeverFallsBackOrChangesOrigin(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"missing current source", func(d *generated.Document) { d.HtmlCurrentSourceJson = nil }},
		{"missing pointer", func(d *generated.Document) { d.HtmlCurrentMaterializationID = pgtype.UUID{} }},
		{"nil pointer", func(d *generated.Document) { d.HtmlCurrentMaterializationID.Bytes = uuid.Nil }},
		{"missing pages", func(d *generated.Document) { d.HtmlCurrentPageCount = pgtype.Int4{} }},
		{"wrong source PDF", func(d *generated.Document) { d.PdfStorageVersionID.String = "wrong" }},
		{"stale printed variables", func(d *generated.Document) { d.VariablesJson = []byte(`{"customer_name":"Recipient AB"}`) }},
		{"origin transport tampering", func(d *generated.Document) { d.HtmlSourceJson = []byte(`{}`) }},
		{"current marked first", func(d *generated.Document) { d.HtmlCurrentMaterializationSequence.Int32 = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, doc := currentFixture(t)
			tc.mutate(doc)
			if err := Validate(doc, false); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid explicit projection accepted: %v", err)
			}
		})
	}
	input, doc := currentFixture(t)
	input.TemplateApprovedBy = uuid.New()
	forged, err := New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlCurrentSourceJson = forged
	if !errors.Is(Validate(doc, false), ErrInvalid) {
		t.Fatal("fresh valid commitment changed original approval")
	}
}
