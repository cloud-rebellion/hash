// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// movedFixture returns a draft whose current materialization is built on a
// newer approved version of the same template. The origin stays version 7.
func movedFixture(t *testing.T, version int32) (Input, *generated.Document) {
	t.Helper()
	input, doc := sourceFixture(t)
	attachSource(t, input, doc)
	origin := bytes.Clone(doc.HtmlSourceJson)
	master, err := json.Marshal(htmlmaster.Master{
		SchemaVersion: 1, HTML: `<p>Customer: <span data-hash-value="customer_name"></span> <span data-hash-value="ref"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer_name", Required: true, MaxChars: 200}, {Name: "ref", Required: false, MaxChars: 50}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Deliver the approved service", MaxChars: 500}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := htmlmaster.CanonicalTemplate(master, []byte(`{"customer_name":"Default AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	input.TemplateVersion, input.TemplateContentSHA256 = version, c.SHA256
	input.MasterJSON, input.DefaultVarsJSON = c.MasterJSON, c.DefaultsJSON
	input.TemplateApprovedBy, input.TemplateApprovedAt = uuid.New(), time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	input.Values = map[string]string{"customer_name": "Recipient AB", "ref": ""}
	doc.VariablesJson, _ = json.Marshal(input.Values)
	doc.PdfStorageKey.String = "org/example/documents/moved.pdf"
	doc.PdfStorageVersionID.String = "opaque-version-2"
	current, err := New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson = origin
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlCurrentSourceJson = current
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 1, Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
	return input, doc
}

func TestHTMLSourceAcceptsForwardTemplateMoveAndKeepsOrigin(t *testing.T) {
	_, doc := movedFixture(t, 8)
	if err := Validate(doc, false); err != nil {
		t.Fatalf("forward move refused: %v", err)
	}
	origin, err := OriginCommitment(doc)
	current, cerr := Commitment(doc)
	if err != nil || cerr != nil || origin == current {
		t.Fatal("origin anchor lost or conflated", err, cerr)
	}
}

func TestHTMLSourceRefusesNonForwardOrFirstMaterializationMove(t *testing.T) {
	for name, tc := range map[string]struct {
		version int32
		mutate  func(*generated.Document)
	}{
		"same version, different approval": {7, nil},
		"older version":                    {6, nil},
		"moved source marked first":        {8, func(d *generated.Document) { d.HtmlCurrentMaterializationSequence.Int32 = 1 }},
	} {
		t.Run(name, func(t *testing.T) {
			_, doc := movedFixture(t, tc.version)
			if tc.mutate != nil {
				tc.mutate(doc)
			}
			if err := Validate(doc, false); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestHTMLSourceRefusesMoveThatChangesSchemaOrParties(t *testing.T) {
	_, doc := movedFixture(t, 8)
	var cur source
	if err := decodeSource(doc.HtmlCurrentSourceJson, &cur); err != nil {
		t.Fatal(err)
	}
	var origin source
	if err := decodeSource(doc.HtmlSourceJson, &origin); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*source){
		"schema":   func(s *source) { s.SchemaVersion = ContractSchemaVersion },
		"parties":  func(s *source) { s.PartyBindings = []PartyBinding{{Slot: "x"}} },
		"template": func(s *source) { s.TemplateID = uuid.New() },
		"doc":      func(s *source) { s.DocumentID = uuid.New() },
		"org":      func(s *source) { s.OrgID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			c := cur
			mutate(&c)
			if approvedLineage(origin, c) {
				t.Fatal("lineage accepted")
			}
		})
	}
	if !approvedLineage(origin, cur) {
		t.Fatal("forward lineage refused")
	}
}
