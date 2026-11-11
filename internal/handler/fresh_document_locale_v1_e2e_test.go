//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/google/uuid"
)

// Real HTTP/session, PostgreSQL, fresh native creator and measured native GET.
// No second mutation changes the language after the creation commits.
func TestFreshDocumentMailLocaleCreationV1E2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	credential, _, _ := documentCreationCredentialE2E(t, f, "rest", false)
	for _, tc := range []struct {
		locale, want string
		status       int
	}{
		{"", "en", http.StatusCreated}, {"sv", "sv", http.StatusCreated}, {"sv-SE", "sv", http.StatusCreated}, {"en", "en", http.StatusCreated}, {"unknown", "", http.StatusBadRequest},
	} {
		t.Run("locale="+tc.locale, func(t *testing.T) {
			name := "Synthetic fresh language " + uuid.NewString()
			input := map[string]any{"name": name, "source_kind": "blocks", "purpose": "document"}
			if tc.locale != "" {
				input["default_locale"] = tc.locale
			}
			response := submitDocumentCreationE2E(f, f.ctx, "rest", credential, input)
			if response.Code != tc.status {
				t.Fatalf("create status=%d want=%d", response.Code, tc.status)
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM documents WHERE org_id=$1 AND name=$2`, f.org, name).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if tc.status != http.StatusCreated {
				if count != 0 {
					t.Fatal("invalid locale committed a document")
				}
				return
			}
			if count != 1 {
				t.Fatal("creation did not commit exactly one document")
			}
			var id uuid.UUID
			if err := f.pool.QueryRow(f.ctx, `SELECT id FROM documents WHERE org_id=$1 AND name=$2`, f.org, name).Scan(&id); err != nil {
				t.Fatal(err)
			}
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
			if err != nil || doc.DefaultLocale != tc.want || doc.SentAt.Valid {
				t.Fatal("creation did not atomically preserve the selected language", err)
			}
			r := httptest.NewRequest(http.MethodGet, f.s.PublicURL+"/api/v1/documents/"+id.String(), nil).WithContext(f.ctx)
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credential})
			read := httptest.NewRecorder()
			f.s.Routes().ServeHTTP(read, r)
			var view struct {
				DefaultLocale string `json:"default_locale"`
			}
			if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &view) != nil || view.DefaultLocale != tc.want {
				t.Fatal("funded native read lost the creation language", read.Code)
			}
		})
	}
	t.Run("plain PDF Swedish birth", func(t *testing.T) {
		if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
				t.Error(err)
			}
		})
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		for key, value := range map[string]string{"name": "Synthetic Swedish PDF", "purpose": "document", "default_locale": "sv"} {
			if err := form.WriteField(key, value); err != nil {
				t.Fatal(err)
			}
		}
		part, err := form.CreateFormFile("pdf", "synthetic.pdf")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(fieldBrowserPDF("Synthetic Swedish PDF")); err != nil {
			t.Fatal(err)
		}
		if err = form.Close(); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents/import", &body).WithContext(f.ctx)
		r.Header.Set("Content-Type", form.FormDataContentType())
		r.Header.Set("Origin", f.s.PublicURL)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credential})
		response := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(response, r)
		var result struct{ Document documentResponse }
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Document.DefaultLocale != "sv" {
			t.Fatal("plain PDF creation did not persist Swedish atomically", response.Code)
		}
		ownedPlainFreshDocumentV1(t, q, result.Document.ID)
	})
	t.Run("designed HTML Swedish birth", func(t *testing.T) {
		h, _ := setupHTMLDocumentCreationE2E(t, &htmlCreationRendererE2E{})
		template := createHTMLTemplateE2E(t, h)
		approveHTMLCreationTemplateE2E(t, h, template)
		cookie := dsrSessionCookieE2E(t, h.s, h.user.ID, h.user.SessionGeneration, time.Hour)
		input := htmlCreationInputE2E(template)
		input.DefaultLocale = "sv"
		input.Purpose = documentpurpose.Document
		response := submitHTMLDocumentCreationE2E(t, h, template.ID, input, cookie)
		var result struct{ Document documentResponse }
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Document.DefaultLocale != "sv" {
			t.Fatal("designed HTML creation did not persist Swedish atomically", response.Code)
		}
		doc, err := h.q.GetDocument(h.ctx, generated.GetDocumentParams{ID: result.Document.ID, OrgID: h.org})
		if err != nil || doc.DefaultLocale != "sv" || len(doc.HtmlSourceJson) == 0 {
			t.Fatal("designed source or selected locale lost", err)
		}
		if purpose, err := documentpurpose.Parse(doc.Metadata); err != nil || purpose != documentpurpose.Document {
			t.Fatal("designed document creation lost its explicit existing authoring purpose", purpose, err)
		}
	})
}
