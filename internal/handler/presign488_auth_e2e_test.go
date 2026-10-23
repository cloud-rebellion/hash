//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These tests exercise the registered HTTP router and real PostgreSQL-backed
// credential middleware in process. The existing owned schema3 protocol fixture
// is enough for an eligibility read and denials before production effects. It
// is not an Object Lock, real renderer, network transport or delivery journey.
type preSignAuthFixture488 struct {
	owned    *ownedPublicReadFixtureV1
	router   http.Handler
	document *generated.Document
}

func newPreSignAuthFixture488(t *testing.T) preSignAuthFixture488 {
	t.Helper()
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	doc := createBrandedDocumentE2E(t, q.f, q.template, q.cookie)
	if doc == nil || !doc.HtmlCurrentMaterializationID.Valid || !doc.HtmlCurrentMaterializationSequence.Valid {
		t.Fatal("actual owned source fixture unavailable")
	}
	// This is an explicit disposable-test opt-in. Production's feature flag
	// remains false until the separate complete journey has qualified it.
	q.f.s.PreSignExecutionEnabled = true
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	return preSignAuthFixture488{owned: q, router: q.f.s.Routes(), document: doc}
}

func (f preSignAuthFixture488) call(t *testing.T, method, path, cookie, bearer string, in any, want int) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if in != nil {
		var err error
		raw, err = json.Marshal(in)
		if err != nil {
			t.Fatal("controlled request encoding failed")
		}
	}
	r := httptest.NewRequest(method, f.owned.f.s.PublicURL+path, bytes.NewReader(raw)).WithContext(f.owned.f.ctx)
	defer r.Body.Close()
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.owned.f.s.PublicURL)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != want {
		sum := sha256.Sum256(w.Body.Bytes())
		t.Fatalf("controlled auth route status=%d want=%d bytes=%d body_sha256=%x", w.Code, want, w.Body.Len(), sum)
	}
	return w
}

func (f preSignAuthFixture488) snapshot(t *testing.T) string {
	t.Helper()
	var out string
	err := f.owned.f.pool.QueryRow(f.owned.f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
	 SELECT jsonb_build_object(
	 'documents',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
	 'recipients',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN(SELECT id FROM owned)),
	 'fields',(SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN(SELECT id FROM owned)),
	 'executions',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM presign_executions e WHERE org_id=$1),
	 'uses',(SELECT COALESCE(jsonb_agg(to_jsonb(u) ORDER BY execution_id),'[]'::jsonb) FROM presign_execution_uses u WHERE org_id=$1),
	 'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY request_id),'[]'::jsonb) FROM presign_execution_requests r WHERE org_id=$1),
	 'preparations',(SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY id),'[]'::jsonb) FROM presign_preparations_v1 p WHERE org_id=$1),
	 'objects',(SELECT COALESCE(jsonb_agg(to_jsonb(o) ORDER BY preparation_id,role),'[]'::jsonb) FROM presign_preparation_objects_v1 o WHERE org_id=$1),
	 'signatures',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN(SELECT id FROM owned)),
	 'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1),
	 'outbox',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM email_deliveries e))::text`, f.owned.f.org).Scan(&out)
	if err != nil {
		t.Fatal("owned auth side-effect inventory unavailable")
	}
	return out
}

func (f preSignAuthFixture488) unchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("refused pre-sign request changed document, recipients, fields, execution/use/request, preparation/object, signature, audit or outbox")
	}
}

func (f preSignAuthFixture488) eligibility(t *testing.T, cookie, bearer string, api bool) presignexecute.IntentV1 {
	t.Helper()
	base := "/api/v1/presign/executions"
	if api {
		base = "/api/automation/v1/presign/executions"
	}
	w := f.call(t, http.MethodGet, base+"/documents/"+f.document.ID.String()+"/eligibility", cookie, bearer, nil, http.StatusOK)
	var view presignexecute.EligibilityV1
	d := json.NewDecoder(bytes.NewReader(w.Body.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&view) != nil || view.SchemaVersion != 1 || view.OrgID != f.owned.f.org || view.UserID != f.owned.f.user.ID ||
		view.DocumentID != f.document.ID || !view.Eligible || view.Source == nil || view.Source.MaterializationID == uuid.Nil ||
		view.Source.MaterializationRevision < 1 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("actual admitted eligibility projection missing")
	}
	// The real source pin makes the denied payload well formed. Deliberately
	// nonexistent authority references grant nothing; the denial asserted by
	// each test must happen at the credential/actor boundary before lookup.
	return presignexecute.IntentV1{RequestID: uuid.New(), ExpectedOrgID: view.OrgID, ExpectedUserID: view.UserID, DocumentID: view.DocumentID,
		DocumentUpdatedAt: view.Source.DocumentUpdatedAt, MaterializationID: view.Source.MaterializationID,
		MaterializationRevision: view.Source.MaterializationRevision, SourceCommitment: view.Source.SourceCommitment,
		Policy: presign.Reference{ID: uuid.New(), Revision: 1, SHA256: strings.Repeat("1", 64)},
		Grant:  presign.Reference{ID: uuid.New(), Revision: 1, SHA256: strings.Repeat("2", 64)}, LawfulBasis: "contract"}
}

func TestPreSign488RegisteredSessionAuthDenialsHaveNoEffectsE2E(t *testing.T) {
	f := newPreSignAuthFixture488(t)
	q := f.owned
	before := f.snapshot(t)
	in := f.eligibility(t, q.cookie, "", false)
	f.unchanged(t, before)
	confirm := presignexecute.ConfirmV1{Intent: in, Receipt: "unconfirmed-controlled-receipt", Confirmed: true}
	base := "/api/v1/presign/executions"
	// A syntactically correct body does not authenticate an ambient session.
	for _, path := range []string{base + "/preview", base} {
		var body any = in
		if path == base {
			body = confirm
		}
		f.call(t, http.MethodPost, path, "", "", body, http.StatusUnauthorized)
		f.unchanged(t, before)
	}
	other, err := q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: q.f.org, Email: uuid.NewString() + "@presign-auth.test", Name: "Other controlled sender", Role: "sender"})
	if err != nil {
		t.Fatal("controlled second actor unavailable")
	}
	otherCookie := dsrSessionCookieE2E(t, q.f.s, other.ID, other.SessionGeneration, time.Hour)
	for _, path := range []string{base + "/preview", base} {
		var body any = in
		if path == base {
			body = confirm
		}
		f.call(t, http.MethodPost, path, otherCookie, "", body, http.StatusForbidden)
		f.unchanged(t, before)
	}
	// Revoke the actual original session through its registered logout route;
	// no artificial context, generation receipt or fake identity is supplied.
	f.call(t, http.MethodPost, "/auth/logout", q.cookie, "", nil, http.StatusOK)
	before = f.snapshot(t)
	for _, path := range []string{base + "/preview", base} {
		var body any = in
		if path == base {
			body = confirm
		}
		f.call(t, http.MethodPost, path, q.cookie, "", body, http.StatusUnauthorized)
		f.unchanged(t, before)
	}
}

func TestPreSign488RegisteredAPIRequiresBothScopesAndRejectsDocumentAgentE2E(t *testing.T) {
	f := newPreSignAuthFixture488(t)
	q := f.owned
	user, err := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "sender"})
	if err != nil {
		t.Fatal("actual sender role unavailable")
	}
	q.f.user = user
	newKey := func(scopes []string, expired bool) (string, uuid.UUID) {
		t.Helper()
		mint, err := auth.MintAPIKey()
		if err != nil {
			t.Fatal("controlled API credential mint failed")
		}
		expiry := pgtype.Timestamptz{}
		if expired {
			expiry = pgtype.Timestamptz{Time: time.Now().UTC().Add(-time.Hour), Valid: true}
		}
		row, err := q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: user.ID, KeyPrefix: mint.Prefix, KeyHash: mint.Hash,
			Name: "Controlled pre-sign auth credential", Scopes: scopes, ExpiresAt: expiry})
		if err != nil {
			t.Fatal("controlled API credential unavailable")
		}
		return mint.Plaintext, row.ID
	}
	both := []string{"write:authoring", "write:workflow"}
	accepted, _ := newKey(both, false)
	before := f.snapshot(t)
	in := f.eligibility(t, "", accepted, true)
	f.unchanged(t, before)
	confirm := presignexecute.ConfirmV1{Intent: in, Receipt: "unconfirmed-controlled-receipt", Confirmed: true}
	authoringOnly, _ := newKey([]string{"write:authoring"}, false)
	workflowOnly, _ := newKey([]string{"write:workflow"}, false)
	expired, _ := newKey(both, true)
	revoked, revokedID := newKey(both, false)
	if _, err = q.f.pool.Exec(q.f.ctx, `DELETE FROM api_keys WHERE org_id=$1 AND id=$2`, q.f.org, revokedID); err != nil {
		t.Fatal("controlled credential revocation failed")
	}
	agent, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal("controlled document credential mint failed")
	}
	if _, err = q.f.q.InsertDocAgentToken(q.f.ctx, generated.InsertDocAgentTokenParams{DocumentID: f.document.ID, OrgID: q.f.org, Prefix: agent.Prefix, KeyHash: agent.Hash,
		Name: "Controlled same-document auth token", Scopes: both, CreatedBy: pgtype.UUID{Bytes: user.ID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true}, MaxUses: 0}); err != nil {
		t.Fatal("controlled document credential unavailable")
	}
	base := "/api/automation/v1/presign/executions"
	for _, entry := range []struct {
		name, key string
		want      int
	}{
		{"missing workflow scope", authoringOnly, http.StatusForbidden},
		{"missing authoring scope", workflowOnly, http.StatusForbidden},
		{"expired API credential", expired, http.StatusUnauthorized},
		{"revoked API credential", revoked, http.StatusUnauthorized},
		{"same-document agent with both scopes", agent.Plaintext, http.StatusForbidden},
	} {
		t.Run(entry.name, func(t *testing.T) {
			for _, path := range []string{base + "/preview", base} {
				var body any = in
				if path == base {
					body = confirm
				}
				f.call(t, http.MethodPost, path, "", entry.key, body, entry.want)
				f.unchanged(t, before)
			}
		})
	}
}
