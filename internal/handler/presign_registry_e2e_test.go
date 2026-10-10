//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
)

// Real router, signed-session admission, live PostgreSQL membership, app-owned
// font bytes and durable original-actor recovery. No document is signed/sent.
func TestPresignRegistryContextFontAndRequestRESTE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	response := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/presign/context", "", cookie)
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("context status=%d", response.Code)
	}
	var context struct {
		OrgID  uuid.UUID `json:"org_id"`
		UserID uuid.UUID `json:"user_id"`
		Self   struct {
			ID                uuid.UUID `json:"id"`
			Name, Email, Role string
		} `json:"self"`
		Fonts              []presign.SignatureStyle       `json:"fonts"`
		Disclosure         presignregistry.DisclosureCopy `json:"disclosure"`
		ExecutionAvailable bool                           `json:"execution_available"`
	}
	if json.Unmarshal(response.Body.Bytes(), &context) != nil || context.OrgID != f.org || context.UserID != f.user.ID || context.Self.ID != f.user.ID || context.Self.Name != f.user.Name || context.Self.Email != f.user.Email || context.Self.Role != "owner" || context.ExecutionAvailable || context.Disclosure != presignregistry.Disclosure() || len(context.Fonts) != 5 {
		t.Fatal("context identity/catalog mismatch")
	}
	for _, font := range context.Fonts {
		w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/presign/fonts/"+url.PathEscape(font.Font), "", cookie)
		digest := sha256.Sum256(w.Body.Bytes())
		if w.Code != 200 || w.Header().Get("Content-Type") != "font/woff2" || w.Header().Get("Cache-Control") != "no-store" || hex.EncodeToString(digest[:]) != font.FontSHA256 {
			t.Fatal("font preview differs from authoritative bundled bytes")
		}
	}
	request := uuid.New()
	path := "/api/v1/presign/requests/" + request.String()
	if w := submitSessionOperationE2E(f.s, http.MethodGet, path, "", cookie); w.Code != 404 {
		t.Fatalf("unconfirmed request status=%d", w.Code)
	}
	in := presignregistry.CloseRequestInput{RequestID: request, ExpectedOrgID: f.org, ExpectedUserID: f.user.ID, Confirmed: true}
	body, _ := json.Marshal(in)
	var original []byte
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodPost} {
		p := path
		if method == http.MethodPost {
			p += "/close"
		}
		w := submitSessionOperationE2E(f.s, method, p, string(body), cookie)
		var outcome presignregistry.Outcome
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &outcome) != nil || outcome.State != "closed" || outcome.Operation != presignregistry.OperationCloseRequest || outcome.Reference != (presign.Reference{}) || outcome.OrgID != f.org || outcome.UserID != f.user.ID || outcome.RequestID != request {
			t.Fatalf("durable close/readback status=%d", w.Code)
		}
		if original == nil {
			original = append([]byte{}, w.Body.Bytes()...)
		} else if string(original) != w.Body.String() {
			t.Fatal("replay changed original durable outcome")
		}
	}
	if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if w := submitSessionOperationE2E(f.s, http.MethodGet, path, "", cookie); w.Code != 200 {
		t.Fatalf("member lost own request recovery=%d", w.Code)
	}
	if w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/presign/grants", "", cookie); w.Code != 403 {
		t.Fatalf("viewer owner catalog admitted=%d", w.Code)
	}
	if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/presign/self-grants/create", `{}`, cookie); w.Code != 403 {
		t.Fatalf("viewer fresh grant admitted=%d", w.Code)
	}
}
