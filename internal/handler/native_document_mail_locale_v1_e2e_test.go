//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// Genuine native Swedish block birth and normal Send, followed
// by actual recipient/staff actions. The existing bounded protocol providers
// and transactional outbox are synthetic; no SMTP worker sends these messages.
func nativeDocumentMailLocaleFixtureV1(t *testing.T, mixedRecipients bool) *nativeNegotiation262 {
	t.Helper()
	q, document := nativeBindingDocument259(t, false, "sv")
	q.f.s.ActionSecret = "synthetic-document-mail-locale-action-key"
	q.f.s.Sign.ActionSecret = q.f.s.ActionSecret
	if document.DefaultLocale != "sv" {
		t.Fatal("native creation did not atomically persist its selected language")
	}
	if mixedRecipients {
		draft := map[string]any{"expected_updated_at": document.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)}
		draft["blocks_json"] = json.RawMessage(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Agreed terms for {{customer}}"},{"id":"sign","type":"signature_field","attrs":{"recipient_role":"signer"}},{"id":"approve","type":"signature_field","attrs":{"recipient_role":"approver"}}]}`)
		input, err := json.Marshal(draft)
		if err != nil {
			t.Fatal(err)
		}
		if response := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+document.ID.String(), string(input), q.cookie); response.Code != http.StatusOK {
			t.Fatal("actual second signature role authoring refused", response.Code)
		}
	}
	if mixedRecipients {
		if response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+document.ID.String()+"/recipients", `{"email":"binding-swedish@example.test","name":"Native Swedish Approver","role":"approver","locale":"sv"}`, q.cookie); response.Code != http.StatusCreated {
			t.Fatal("actual Swedish recipient override refused", response.Code)
		}
	}
	if response := nativeBindingPublic259(q, q.f.ctx, document.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie); response.Code != http.StatusOK {
		t.Fatal("actual unresolved source definition refused", response.Code)
	}
	if response := submitSessionOperationE2E(q.f.s, http.MethodPut, "/api/v1/automation-preferences", `{"expected_revision":0,"notify_viewed":true,"notify_signed":true}`, q.cookie); response.Code != http.StatusOK {
		t.Fatal("actual owner notification preference refused", response.Code)
	}
	n := &nativeNegotiation262{q: q, document: document}
	if !mixedRecipients {
		n.token = n.sendV1(t)
	} else {
		response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+document.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
		var sent sendDocumentResponse
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || len(sent.Links) != 2 {
			t.Fatal("actual mixed-language native Send refused", response.Code)
		}
		for _, link := range sent.Links {
			if link.Role == "signer" {
				parsed, err := url.Parse(link.URL)
				if err != nil || !strings.HasPrefix(parsed.Path, "/sign/") || n.token != "" {
					t.Fatal("actual signer invitation absent or duplicated")
				}
				n.recipient, n.token = link.RecipientID, strings.TrimPrefix(parsed.Path, "/sign/")
			}
		}
		if n.token == "" {
			t.Fatal("actual signer invitation missing")
		}
	}
	n.noticeDigest = nativeCommentNotice163V1(t, q, n.token)
	parties, err := q.f.q.ListRecipientsByDocument(q.f.ctx, document.ID)
	expected := 1
	if mixedRecipients {
		expected = 2
	}
	if err != nil || len(parties) != expected {
		t.Fatal("explicit recipient language was overridden by the document", err)
	}
	for _, party := range parties {
		if party.Email == "binding-native@example.test" && party.Locale != "en" || party.Email == "binding-swedish@example.test" && party.Locale != "sv" {
			t.Fatal("actual recipient language override changed")
		}
	}
	return n
}

func nativeDocumentMailBodyV1(t *testing.T, n *nativeNegotiation262, to, subjectPattern string) string {
	t.Helper()
	rows, err := n.q.f.pool.Query(n.q.f.ctx, "SELECT html_body FROM email_deliveries WHERE smtp_org_id=$1 AND to_email=$2 AND subject LIKE $3 ORDER BY created_at,id", n.q.f.org, to, subjectPattern)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var body string
	count := 0
	for rows.Next() {
		if err := rows.Scan(&body); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if rows.Err() != nil || count != 1 {
		t.Fatal("expected exactly one scoped notification", subjectPattern, count, rows.Err())
	}
	return body
}

func nativeDocumentQueuedMailHashesV1(t *testing.T, n *nativeNegotiation262) map[uuid.UUID][32]byte {
	t.Helper()
	rows, err := n.q.f.pool.Query(n.q.f.ctx, "SELECT id,subject,html_body,text_body FROM email_deliveries WHERE smtp_org_id=$1 ORDER BY id", n.q.f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[uuid.UUID][32]byte{}
	for rows.Next() {
		var id uuid.UUID
		var subject, body, text string
		if err := rows.Scan(&id, &subject, &body, &text); err != nil {
			t.Fatal(err)
		}
		result[id] = sha256.Sum256([]byte(subject + "\x00" + body + "\x00" + text))
	}
	if rows.Err() != nil || len(result) == 0 {
		t.Fatal("actual initial outbox missing", rows.Err())
	}
	return result
}

func TestNativeDocumentMailLocaleV1E2E(t *testing.T) {
	t.Run("document owner and explicit recipient languages remain distinct", func(t *testing.T) {
		n := nativeDocumentMailLocaleFixtureV1(t, true)
		owner, recipient := n.q.f.user.Email, "binding-native@example.test"
		// Context bootstrap is read-only. Like the real ceremony, explicitly
		// acknowledge its current notice before recording the first view.
		view := httptest.NewRequest(http.MethodPost, n.q.f.s.PublicURL+"/sign/"+n.token+"/view", strings.NewReader(`{}`)).WithContext(n.q.f.ctx)
		view.Header.Set("Content-Type", "application/json")
		view.Header.Set("Origin", n.q.f.s.PublicURL)
		view.Header.Set(signerNoticeDigestHeader, n.noticeDigest)
		viewed := httptest.NewRecorder()
		n.q.f.s.Routes().ServeHTTP(viewed, view)
		if viewed.Code != http.StatusOK {
			t.Fatal("actual notice-bound first view refused", viewed.Code)
		}
		initial := nativeDocumentQueuedMailHashesV1(t, n)
		if body := nativeDocumentMailBodyV1(t, n, owner, "Hash: dokument öppnat"); !strings.Contains(body, "Öppna Hash") {
			t.Fatal("actual opt-in first-view notice ignored document language")
		}
		response := httptest.NewRecorder()
		n.q.f.s.Routes().ServeHTTP(response, nativeCommentRequest163V1(t, n.q, n.q.f.ctx, n.document, "sender", n.token, n.noticeDigest, n.q.cookie))
		if response.Code != http.StatusCreated {
			t.Fatal("actual sender comment refused", response.Code)
		}
		if body := nativeDocumentMailBodyV1(t, n, recipient, "New comment on %"); !strings.Contains(body, nativeCommentBody163V1) || strings.Contains(body, "Ny kommentar") {
			t.Fatal("explicit English recipient comment language or full text lost")
		}
		if body := nativeDocumentMailBodyV1(t, n, "binding-swedish@example.test", "Ny kommentar om %"); !strings.Contains(body, nativeCommentBody163V1) || strings.Contains(body, "New comment") {
			t.Fatal("explicit Swedish recipient comment language or full text lost")
		}
		n.noticeDigest = nativeCommentNotice163V1(t, n.q, n.token)
		response = httptest.NewRecorder()
		n.q.f.s.Routes().ServeHTTP(response, nativeCommentRequest163V1(t, n.q, n.q.f.ctx, n.document, "signer", n.token, n.noticeDigest, n.q.cookie))
		if response.Code != http.StatusCreated {
			t.Fatal("actual recipient comment refused", response.Code)
		}
		if body := nativeDocumentMailBodyV1(t, n, owner, "Ny kommentar om %"); !strings.Contains(body, nativeCommentBody163V1) || !strings.Contains(body, "Öppna dokumentet för att svara") {
			t.Fatal("owner comment language or full text lost")
		}
		n.noticeDigest = nativeCommentNotice163V1(t, n.q, n.token)
		if response := n.requestV1(); response.Code != http.StatusOK {
			t.Fatal("actual language-scoped request for changes refused", response.Code)
		}
		body := nativeDocumentMailBodyV1(t, n, owner, "% har begärt ändringar i %")
		for _, want := range []string{"Godkänn", "Avvisa", "Öppna dokumentet", "Please adjust the agreed terms", "Agreed terms", "Native negotiation fixture", "Revised agreed terms"} {
			if !strings.Contains(body, want) {
				t.Fatal("request language or complete request data lost", want)
			}
		}
		current := nativeDocumentQueuedMailHashesV1(t, n)
		for id, before := range initial {
			if current[id] != before {
				t.Fatal("later actions rewrote already queued email bytes")
			}
		}
		nativeBindingMeasurement259(t, n.q.f, n.document.ID)
		ownedRevisionConsumedV1(t, n.q)
		n.q.assertObserversOnlyV1(t)
	})
	t.Run("decline owner language follows the saved document", func(t *testing.T) {
		n := nativeDocumentMailLocaleFixtureV1(t, false)
		request := httptest.NewRequest(http.MethodPost, n.q.f.s.PublicURL+"/sign/"+n.token+"/decline", bytes.NewBufferString(`{"reason":"Synthetic decline comment"}`)).WithContext(n.q.f.ctx)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", n.q.f.s.PublicURL)
		request.Header.Set(signerNoticeDigestHeader, n.noticeDigest)
		response := httptest.NewRecorder()
		n.q.f.s.Routes().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatal("actual synthetic decline refused", response.Code)
		}
		if body := nativeDocumentMailBodyV1(t, n, n.q.f.user.Email, "% har avböjt %"); !strings.Contains(body, "Angivet skäl") || !strings.Contains(body, "Synthetic decline comment") {
			t.Fatal("owner decline language or full reason lost")
		}
		ownedRevisionConsumedV1(t, n.q)
		n.q.assertObserversOnlyV1(t)
	})
	t.Run("completion retains recipient override and document owner language", func(t *testing.T) {
		n := nativeDocumentMailLocaleFixtureV1(t, false)
		request := httptest.NewRequest(http.MethodPost, n.q.f.s.PublicURL+"/sign/"+n.token+"/sign", bytes.NewBufferString(`{"typed_name":"Native Binding Signer","font":"Caveat"}`)).WithContext(n.q.f.ctx)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", n.q.f.s.PublicURL)
		request.Header.Set(signerNoticeDigestHeader, n.noticeDigest)
		response := httptest.NewRecorder()
		n.q.f.s.Routes().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatal("actual synthetic signature refused", response.Code)
		}
		document, err := n.q.f.q.GetDocument(n.q.f.ctx, generated.GetDocumentParams{ID: n.document.ID, OrgID: n.q.f.org})
		if err != nil || document.Status != "completed" {
			t.Fatal("actual native completion absent", err)
		}
		if body := nativeDocumentMailBodyV1(t, n, n.q.f.user.Email, "% – signeringen är klar"); !strings.Contains(body, "Ladda ner färdig PDF") || !strings.Contains(body, "Ladda ner granskningscertifikat") {
			t.Fatal("owner completion did not use document language")
		}
		if body := nativeDocumentMailBodyV1(t, n, "binding-native@example.test", "Your signed copy of %"); !strings.Contains(body, "Download signed PDF") || strings.Contains(body, "Ladda ner färdig PDF") {
			t.Fatal("recipient completion lost its explicit English language")
		}
		if body := nativeDocumentMailBodyV1(t, n, n.q.f.user.Email, "Hash: mottagaren har signerat"); !strings.Contains(body, "Öppna Hash") {
			t.Fatal("actual signed-event notice ignored document language")
		}
		ownedRevisionConsumedV1(t, n.q)
		n.q.assertObserversOnlyV1(t)
	})
}
