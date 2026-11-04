//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"html"
	"net/http"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
)

// Genuine owner HTTP editions, native create/review/two-party Send and manual
// reminder. SQL only observes actual immutable confirmation/outbox rows; no
// business/cache/measurement/grant/receipt rows are inserted by this test.
func TestTenantPresentation767NativeInviteReminderFrozenCompanyAndCurrentFromE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindReminder} {
		response := ownedBlocksTemplateCallV1(t, f, q.cookie, http.MethodPut, "/api/v1/email-templates/"+kind, map[string]any{"expected_revision": 0, "subject_template": "Company {{org_name}}", "html_template": "<p>Company {{org_name}} for {{recipient_name}}</p>", "text_template": "Company {{org_name}} for {{recipient_name}}"})
		if response.Code != http.StatusOK {
			t.Fatalf("native owner company edition=%d", response.Code)
		}
	}
	const firstFrom = "Original installation transport"
	const currentFrom = "Changed current installation transport"
	f.s.Send.OrgName = firstFrom
	document, parties := q.createSentV1(t)
	confirmation, err := f.q.GetDocumentLawfulBasisConfirmation(f.ctx, generated.GetDocumentLawfulBasisConfirmationParams{DocumentID: document.ID, OrgID: f.org})
	if err != nil || confirmation == nil {
		t.Fatal("native send-frozen controller unavailable", err)
	}
	company := strings.TrimSpace(confirmation.ControllerName)
	if company == "" || company == firstFrom || company == currentFrom {
		t.Fatal("fixture lost distinct real tenant/controller and installation identities")
	}
	confirmationSnapshot := func() string {
		t.Helper()
		var out string
		if err := f.pool.QueryRow(f.ctx, `SELECT to_jsonb(c)::text FROM document_lawful_basis_confirmations c WHERE document_id=$1 AND org_id=$2`, document.ID, f.org).Scan(&out); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- actual confirmation immutability oracle only
		return out
	}
	beforeConfirmation := confirmationSnapshot()
	addresses := make([]string, len(parties))
	for i, party := range parties {
		recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: party.RecipientID, OrgID: f.org})
		if err != nil || recipient == nil || recipient.DocumentID != document.ID {
			t.Fatal("actual native recipient unavailable", err)
		}
		addresses[i] = recipient.Email
	}
	type actualMail struct {
		id                         uuid.UUID
		body, text, from, snapshot string
	}
	readMails := func() []actualMail {
		t.Helper()
		rows, err := f.pool.Query(f.ctx, `SELECT id,html_body,text_body,from_name,to_jsonb(m)::text FROM email_deliveries m WHERE smtp_org_id=$1 AND smtp_purpose='workspace' AND to_email=ANY($2::text[]) ORDER BY id`, f.org, addresses)
		if err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- actual native rendered queue only; no fake source/admission rows
		defer rows.Close()
		var out []actualMail
		for rows.Next() {
			var m actualMail
			if err := rows.Scan(&m.id, &m.body, &m.text, &m.from, &m.snapshot); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(m.body, html.EscapeString(company)) || !strings.Contains(m.text, company) {
				t.Fatal("native email used installation or foreign company text")
			}
			out = append(out, m)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	initial := readMails()
	if len(initial) != len(parties) {
		t.Fatal("native Send did not emit exact invitations", len(initial))
	}
	frozen := map[uuid.UUID]string{}
	for _, mail := range initial {
		if mail.from != firstFrom {
			t.Fatal("tenant text changed existing From behavior")
		}
		frozen[mail.id] = mail.snapshot
	}
	f.s.Send.OrgName = currentFrom
	response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+document.ID.String()+"/remind", "", q.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("genuine native reminder=%d", response.Code)
	}
	after := readMails()
	if len(after) != 2*len(parties) {
		t.Fatal("native reminder did not emit exactly remaining parties", len(after))
	}
	for _, mail := range after {
		if previous, ok := frozen[mail.id]; ok {
			if previous != mail.snapshot {
				t.Fatal("new reminder rewrote already queued invitation")
			}
		} else if mail.from != currentFrom {
			t.Fatal("new presentation froze or replaced current From behavior")
		}
	}
	if confirmationSnapshot() != beforeConfirmation {
		t.Fatal("presentation changed the legal confirmation")
	}
	ownedPlainAssertDrainedV1(t, q)
}
