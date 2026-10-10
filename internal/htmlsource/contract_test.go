// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestReviewedContractSourcePinsIdentityAndDefendsCopies(t *testing.T) {
	input, doc, rows := testfixture.HTMLContract(t)
	original := bytes.Clone(doc.HtmlSourceJson)
	if err := htmlsource.Validate(doc, true); err != nil {
		t.Fatal(err)
	}
	if err := htmlsource.ValidateContractParties(doc, rows); err != nil {
		t.Fatal(err)
	}
	var header struct {
		SchemaVersion int                       `json:"schema_version"`
		Bindings      []htmlsource.PartyBinding `json:"party_bindings"`
	}
	if err := json.Unmarshal(original, &header); err != nil || header.SchemaVersion != 2 || len(header.Bindings) != 2 || header.Bindings[0].Slot != "customer" || header.Bindings[1].Slot != "provider" {
		t.Fatalf("missing versioned, canonical binding tuple: %#v %v", header, err)
	}
	before, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	recovered.PartyBindings[0].RecipientID = uuid.New()
	input.PartyBindings[0].RecipientID = uuid.New()
	profile, err := htmlsource.ContractProfile(doc)
	if err != nil || profile == nil {
		t.Fatal(err)
	}
	profile.Parties[0].RepresentativeName = "changed_copy"
	parties, err := htmlsource.ContractParties(doc)
	if err != nil || len(parties) != 2 {
		t.Fatal(err)
	}
	parties[0].Name = "changed_copy"
	after, err := htmlsource.Commitment(doc)
	if err != nil || after != before || !bytes.Equal(original, doc.HtmlSourceJson) {
		t.Fatal("mutable accessor changed commitment", err)
	}
	if err := htmlsource.ValidateContractParties(doc, rows); err != nil {
		t.Fatal(err)
	}
}

func TestReviewedContractSourceRejectsIncompleteOrAmbiguousBindings(t *testing.T) {
	for _, name := range []string{"absent", "one", "nil", "duplicate_id", "wrong_slot", "third", "signature_downgrade"} {
		t.Run(name, func(t *testing.T) {
			input, doc, _ := testfixture.HTMLContract(t)
			switch name {
			case "absent":
				input.PartyBindings = nil
			case "one":
				input.PartyBindings = input.PartyBindings[:1]
			case "nil":
				input.PartyBindings[0].RecipientID = uuid.Nil
			case "duplicate_id":
				input.PartyBindings[0].RecipientID = input.PartyBindings[1].RecipientID
			case "wrong_slot":
				input.PartyBindings[0].Slot = "signer"
			case "third":
				input.PartyBindings = append(input.PartyBindings, htmlsource.PartyBinding{Slot: "other", RecipientID: uuid.New()})
			case "signature_downgrade":
				doc.RequiresSignature = false
			}
			if _, err := htmlsource.New(input, doc); !errors.Is(err, htmlsource.ErrInvalid) {
				t.Fatalf("invalid binding accepted: %v", err)
			}
		})
	}
	for _, key := range []string{"Slot", "Recipient_ID"} {
		t.Run(key, func(t *testing.T) {
			_, doc, _ := testfixture.HTMLContract(t)
			old := "slot"
			if key != "Slot" {
				old = "recipient_id"
			}
			doc.HtmlSourceJson = bytes.Replace(doc.HtmlSourceJson, []byte(`"`+old+`"`), []byte(`"`+key+`"`), 1)
			if err := htmlsource.Validate(doc, false); !errors.Is(err, htmlsource.ErrInvalid) {
				t.Fatalf("case alias admitted: %v", err)
			}
		})
	}
}

func TestReviewedContractRecipientsCannotShrinkOrChangePrintedIntention(t *testing.T) {
	for _, name := range []string{"missing_provider", "replacement_id", "name", "email_case", "role", "foreign_document", "duplicate_row", "extra_party", "signature_downgrade"} {
		t.Run(name, func(t *testing.T) {
			_, doc, rows := testfixture.HTMLContract(t)
			switch name {
			case "missing_provider":
				rows = rows[1:]
			case "replacement_id":
				rows[0].ID = uuid.New()
			case "name":
				rows[0].Name = "An independently edited name"
			case "email_case":
				rows[0].Email = "Provider@example.test"
			case "role":
				rows[0].Role = "signer"
			case "foreign_document":
				rows[0].DocumentID = uuid.New()
			case "duplicate_row":
				rows[1] = rows[0]
			case "extra_party":
				rows = append(rows, &generated.Recipient{ID: uuid.New(), DocumentID: doc.ID, Role: "other"})
			case "signature_downgrade":
				doc.RequiresSignature = false
			}
			if err := htmlsource.ValidateContractParties(doc, rows); !errors.Is(err, htmlsource.ErrInvalid) {
				t.Fatalf("changed intention admitted: %v", err)
			}
		})
	}
}

func contractRevision(t *testing.T, changeBinding bool) (*generated.Document, []*generated.Recipient) {
	t.Helper()
	input, doc, rows := testfixture.HTMLContract(t)
	origin := bytes.Clone(doc.HtmlSourceJson)
	input.Values["customer_name"] = "New declared customer representative"
	input.Values["customer_email"] = "NewCustomer@example.test"
	if changeBinding {
		input.PartyBindings[1].RecipientID = uuid.New()
	}
	doc.VariablesJson, _ = json.Marshal(input.Values)
	doc.PdfStorageKey.String = "org/synthetic/documents/revision.pdf"
	doc.PdfStorageVersionID.String = "synthetic-revision-version"
	current, err := htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson = origin
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlCurrentSourceJson = current
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
	return doc, rows
}

func TestReviewedContractRevisionKeepsUUIDsAndRequiresFreshIdentitiesAndReview(t *testing.T) {
	doc, rows := contractRevision(t, false)
	origin := bytes.Clone(doc.HtmlSourceJson)
	if err := htmlsource.Validate(doc, false); err != nil {
		t.Fatal(err)
	}
	if err := htmlsource.ValidateContractParties(doc, rows); !errors.Is(err, htmlsource.ErrInvalid) {
		t.Fatal("old printed identity survived revision", err)
	}
	rows[1].Name, rows[1].Email = "New declared customer representative", "NewCustomer@example.test"
	if err := htmlsource.ValidateContractParties(doc, rows); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(origin, doc.HtmlSourceJson) {
		t.Fatal("revision rewrote original source")
	}
	if err := htmlsource.Validate(doc, true); !errors.Is(err, htmlsource.ErrReviewRequired) {
		t.Fatal("revision inherited same-PDF review", err)
	}
	doc.HtmlReviewedMaterializationID = doc.HtmlCurrentMaterializationID
	if err := htmlsource.Validate(doc, true); err != nil {
		t.Fatal(err)
	}
	forged, _ := contractRevision(t, true)
	if err := htmlsource.Validate(forged, false); !errors.Is(err, htmlsource.ErrInvalid) {
		t.Fatal("new valid commitment changed pinned intended recipient", err)
	}
}

func TestReviewedContractSourceBindingsSurviveJSONTransportOrder(t *testing.T) {
	_, doc, rows := testfixture.HTMLContract(t)
	original, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(doc.HtmlSourceJson, &raw); err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson, err = json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := htmlsource.Commitment(doc)
	if err != nil || original != changed {
		t.Fatal("JSONB formatting changed contract commitment", err)
	}
	slices.Reverse(rows)
	if err := htmlsource.ValidateContractParties(doc, rows); err != nil {
		t.Fatal(err)
	}
}
