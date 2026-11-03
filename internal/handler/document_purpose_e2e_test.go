//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func submitDocumentPurposeE2E(f lifecycleAuthorizationFixture, cookie string, id uuid.UUID, stamp string, purpose string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(map[string]any{"expected_updated_at": stamp, "purpose": purpose})
	r := httptest.NewRequest(http.MethodPatch, f.s.PublicURL+"/api/v1/documents/"+id.String(), bytes.NewReader(raw)).WithContext(f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

// Actual PostgreSQL/native factory and ordinary middleware; no provider or mail
// tests. These are authored/compile-only locally until a real owned PG fixture.
func TestDocumentPurposeAtomicCreationAndNativeSendFenceE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f, _ := setupDocumentCreationE2E(t, "blocks")
			credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
			name := "Purpose explicit " + transport
			w := submitDocumentCreationE2E(f, f.ctx, transport, credential, map[string]any{"name": name, "source_kind": "blocks", "purpose": "document"})
			want := http.StatusCreated
			if transport == "mcp" {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("create=%d %s", w.Code, w.Body.String())
			}
			var id uuid.UUID
			if err := f.pool.QueryRow(f.ctx, `SELECT id FROM documents WHERE org_id=$1 AND name=$2`, f.org, name).Scan(&id); err != nil {
				t.Fatal(err)
			}
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			if p, err := documentpurpose.Parse(doc.Metadata); err != nil || p != documentpurpose.Document {
				t.Fatal("creation purpose not atomically stored", p, err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			f.doc = doc
			before := f.snapshot(t)
			if got := f.submit("send", cookie); got.Code != http.StatusConflict {
				t.Fatalf("non-signing Send=%d %s", got.Code, got.Body.String())
			}
			f.assertUnchanged(t, before)
			stamp := doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
			if got := submitDocumentPurposeE2E(f, cookie, id, doc.UpdatedAt.Time.Add(-time.Second).UTC().Format(time.RFC3339Nano), "presentation"); got.Code != http.StatusPreconditionFailed {
				t.Fatalf("stale purpose=%d %s", got.Code, got.Body.String())
			}
			if got := submitDocumentPurposeE2E(f, cookie, id, stamp, "presentation"); got.Code != http.StatusOK {
				t.Fatalf("purpose patch=%d %s", got.Code, got.Body.String())
			}
			current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(doc.BlocksJson, current.BlocksJson) || !bytes.Equal(doc.VariablesJson, current.VariablesJson) || documentpurpose.Response(current.Metadata) != documentpurpose.Presentation {
				t.Fatal("purpose patch rewrote source")
			}
			// This ordinary native Get proves the actual M92 response measurement was
			// refreshed, not merely a synthetic success response from the mutation.
			r := httptest.NewRequest(http.MethodGet, f.s.PublicURL+"/api/v1/documents/"+id.String(), nil).WithContext(f.ctx)
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
			get := httptest.NewRecorder()
			f.s.Routes().ServeHTTP(get, r)
			if get.Code != http.StatusOK {
				t.Fatalf("post-purpose native read=%d %s", get.Code, get.Body.String())
			}
		})
	}
}
func TestDocumentPurposeCannotReclassifyRecipientsOrSentEvidenceE2E(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(map[bool]string{false: "recipient draft", true: "sent"}[sent], func(t *testing.T) {
			f := setupLifecycleAuthorizationE2E(t, "sender", sent, false)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			before := f.snapshot(t)
			got := submitDocumentPurposeE2E(f, cookie, f.doc.ID, f.doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "document")
			if got.Code != http.StatusConflict {
				t.Fatalf("protected purpose edit=%d %s", got.Code, got.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}
