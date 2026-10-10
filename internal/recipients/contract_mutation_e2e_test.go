//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package recipients

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestReviewedContractRecipientMutationsPreserveExactPrintedPartiesE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete_provider", "delete_customer", "change_name", "change_email", "change_role"} {
		t.Run(operation, func(t *testing.T) {
			f := setupRecipientMutationE2E(t)
			rows := seedReviewedContractRecipientsE2E(t, f)
			before := f.snapshot(t)
			actor := f.actor(t)
			var result *generated.Recipient
			var err error
			switch operation {
			case "create":
				result, err = f.engine.Create(f.ctx, actor, f.doc.ID, f.values())
			case "delete_provider":
				result, err = f.engine.Delete(f.ctx, actor, f.doc.ID, rows[0].ID)
			case "delete_customer":
				result, err = f.engine.Delete(f.ctx, actor, f.doc.ID, rows[1].ID)
			case "change_name":
				name := "Different provider representative"
				result, err = f.engine.Update(f.ctx, actor, f.doc.ID, rows[0].ID, Patch{Name: &name})
			case "change_email":
				email := "different@example.test"
				result, err = f.engine.Update(f.ctx, actor, f.doc.ID, rows[0].ID, Patch{Email: &email})
			case "change_role":
				role := "signer"
				result, err = f.engine.Update(f.ctx, actor, f.doc.ID, rows[0].ID, Patch{Role: &role})
			}
			var validation *ValidationError
			if result != nil || !errors.As(err, &validation) || validation.Field != "contract_party" {
				t.Fatalf("operation=%s result=%t error=%v", operation, result != nil, err)
			}
			f.assertUnchanged(t, before)
			if f.logger.published != 0 {
				t.Fatalf("refused contract edit published=%d", f.logger.published)
			}
		})
	}
}

func TestReviewedContractRecipientRoutingEditRetainsBindingAndAuditE2E(t *testing.T) {
	f := setupRecipientMutationE2E(t)
	rows := seedReviewedContractRecipientsE2E(t, f)
	beforeSource := string(f.doc.HtmlSourceJson)
	locale, order := "SV-se", int32(4)
	result, err := f.engine.Update(f.ctx, f.actor(t), f.doc.ID, rows[0].ID, Patch{Locale: &locale, OrderIndex: &order})
	if err != nil || result == nil {
		t.Fatalf("routing edit result=%t error=%v", result != nil, err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.orgID})
	if err != nil {
		t.Fatal(err)
	}
	currentRows, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := htmlsource.ValidateContractParties(doc, currentRows); err != nil {
		t.Fatalf("routing edit broke party binding: %v", err)
	}
	if string(doc.HtmlSourceJson) != beforeSource || result.ID != rows[0].ID || result.Name != rows[0].Name || result.Email != rows[0].Email || result.Role != rows[0].Role || result.Locale != "sv" || result.OrderIndex != order {
		t.Fatal("routing edit changed committed identity or lost normalized routing values")
	}
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind='recipient.updated'`, doc.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 || f.logger.published != 1 {
		t.Fatalf("routing audit/publication=%d/%d", events, f.logger.published)
	}
}

func seedReviewedContractRecipientsE2E(t *testing.T, f *recipientMutationFixture) []*generated.Recipient {
	t.Helper()
	input, synthetic, expected := testfixture.HTMLContract(t)
	sha, err := hex.DecodeString(input.TemplateContentSHA256)
	if err != nil {
		t.Fatal(err)
	}
	template, err := f.q.CreateHTMLTemplate(f.ctx, generated.CreateHTMLTemplateParams{OrgID: f.orgID, Name: "Synthetic approved contract",
		HtmlMasterJson: input.MasterJSON, VariablesJson: input.DefaultVarsJSON, CreatedBy: f.user.ID, HtmlContentSha256: sha})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.orgID, SenderID: f.user.ID,
		TemplateID: pgtype.UUID{Bytes: template.ID, Valid: true}, Name: "Synthetic contract recipient guard",
		PdfStorageKey: synthetic.PdfStorageKey, PdfSha256: synthetic.PdfSha256, PdfStorageVersionID: synthetic.PdfStorageVersionID, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	variables, err := json.Marshal(input.Values)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = f.q.FreezeDocumentVariables(f.ctx, generated.FreezeDocumentVariablesParams{ID: doc.ID, OrgID: f.orgID, VariablesJson: variables, ExpectedUpdatedAt: doc.UpdatedAt})
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]*generated.Recipient, 0, 2)
	input.PartyBindings = nil
	for _, representative := range expected {
		_, hash, err := auth.MintMagicToken()
		if err != nil {
			t.Fatal(err)
		}
		row, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: representative.Role,
			Name: representative.Name, Email: representative.Email, Locale: "en", OrderIndex: representative.OrderIndex,
			MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
		input.PartyBindings = append(input.PartyBindings, htmlsource.PartyBinding{Slot: row.Role, RecipientID: row.ID})
	}
	input.TemplateID, input.TemplateApprovedBy = template.ID, f.user.ID
	raw, err := htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = f.q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: f.orgID, HtmlSourceJson: raw, ExpectedUpdatedAt: doc.UpdatedAt})
	if err != nil {
		t.Fatal(err)
	}
	f.doc, f.recipient = doc, rows[0]
	for _, field := range testfixture.ContractSignatureFields(doc, rows) {
		if _, err := f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: f.orgID,
			RecipientID: field.RecipientID, Type: field.Type, Page: field.Page, XPct: field.XPct, YPct: field.YPct,
			WPct: field.WPct, HPct: field.HPct, Required: true, Label: pgtype.Text{String: "Synthetic required signature", Valid: true}, OptionsJson: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}
