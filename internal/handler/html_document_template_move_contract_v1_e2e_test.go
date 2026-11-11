//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
)

// Signing-contract documents keep their party bindings across a move. A move to
// a design with another contract kind is a schema change and is refused.
func contractMoveMasterE2E(t *testing.T, mutate func(*htmlmaster.Master)) (json.RawMessage, json.RawMessage) {
	t.Helper()
	input, _, _ := testfixture.HTMLContract(t)
	var master htmlmaster.Master
	if err := json.Unmarshal(input.MasterJSON, &master); err != nil {
		t.Fatal(err)
	}
	mutate(&master)
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	extra := map[string]string{"effective_date": "2027-01-01", "duration": "12 months"}
	defaults := map[string]string{}
	for _, v := range master.Values {
		if text, ok := input.Values[v.Name]; ok {
			defaults[v.Name] = text
		} else if text, ok := extra[v.Name]; ok {
			defaults[v.Name] = text
		}
	}
	raw2, _ := json.Marshal(defaults)
	return raw, raw2
}

func TestHTMLDocumentTemplateMoveContractKeepsPartyBindingsE2E(t *testing.T) {
	f, _, _, doc, cookie := setupHTMLContractDocumentE2E(t)
	before, err := htmlsource.InputForCurrent(doc)
	if err != nil || len(before.PartyBindings) != 2 {
		t.Fatal("fixture has no party bindings", err)
	}
	master, defaults := contractMoveMasterE2E(t, func(m *htmlmaster.Master) { m.HTML = "<h1>Second contract design</h1>" + m.HTML })
	target := publishRawTemplateVersionE2E(t, f, doc, cookie, 1, master, defaults, true)
	w := submitTemplateMoveE2E(t, f, templateMoveBodyE2E(t, doc, target), cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("contract move=%d %s", w.Code, w.Body.String())
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	after, err := htmlsource.InputForCurrent(current)
	if err != nil || after.TemplateVersion != 2 || len(after.PartyBindings) != 2 {
		t.Fatalf("contract move lost the version or bindings: %v %+v", err, after.PartyBindings)
	}
	for i, b := range after.PartyBindings {
		if b != before.PartyBindings[i] {
			t.Fatalf("party binding %d changed: %+v != %+v", i, b, before.PartyBindings[i])
		}
	}
	if after.Values["customer_email"] != before.Values["customer_email"] || after.Values["provider_email"] != before.Values["provider_email"] {
		t.Fatal("party identity values changed during the move")
	}
}

func TestHTMLDocumentTemplateMoveContractKindChangeIsRefusedE2E(t *testing.T) {
	f, _, _, doc, cookie := setupHTMLContractDocumentE2E(t)
	master, defaults := contractMoveMasterE2E(t, func(m *htmlmaster.Master) {
		p := m.ContractProfile
		p.Kind = "b2b_services"
		p.Terms = nil
		for _, n := range []string{"scope", "price", "currency", "tax", "payment_terms", "effective_date", "duration", "termination"} {
			switch n {
			case "effective_date", "duration":
				m.Values = append(m.Values, htmlmaster.Value{Name: n, Required: true, MaxChars: 500})
				m.HTML += `<p><span data-hash-value="` + n + `"></span></p>`
				p.Terms = append(p.Terms, htmlmaster.ContractTerm{Name: n, Value: n})
			case "termination":
				m.Sections = append(m.Sections, htmlmaster.Section{Name: n, DefaultText: "Thirty days notice", MaxChars: 500})
				m.HTML += `<div data-hash-section="termination"></div>`
				p.Terms = append(p.Terms, htmlmaster.ContractTerm{Name: n, Section: n})
			default:
				p.Terms = append(p.Terms, htmlmaster.ContractTerm{Name: n, Value: n})
			}
		}
	})
	target := publishRawTemplateVersionE2E(t, f, doc, cookie, 1, master, defaults, true)
	before := revisionStateE2E(t, f)
	if w := submitTemplateMoveE2E(t, f, templateMoveBodyE2E(t, doc, target), cookie); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("contract kind change=%d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) {
		t.Fatal("refused move changed document state")
	}
}
