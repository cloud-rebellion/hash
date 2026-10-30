// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These CAS regressions need actual current source measurements. The original
// public creator and PATCH are the only positive producers; stale/refusal
// stimuli below never backfill a source or claim a version from raw SQL.
func nativeRevisionCreateE2E(t *testing.T, f lifecycleAuthorizationFixture, name string, blocks, variables json.RawMessage) (*generated.Document, error) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "source_kind": "blocks", "blocks_json": blocks, "variables_json": variables})
	if err != nil {
		return nil, err
	}
	w := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, "/api/v1/documents", string(body), dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	var created documentResponse
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil {
		return nil, fmt.Errorf("actual native revision creator=%d", w.Code)
	}
	return f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
}

func nativeRevisionEditE2E(t *testing.T, f lifecycleAuthorizationFixture, document *generated.Document, blocks, variables json.RawMessage) (*generated.Document, error) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"expected_updated_at": document.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "blocks_json": blocks, "variables_json": variables})
	if err != nil {
		return nil, err
	}
	w := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPatch, "/api/v1/documents/"+document.ID.String(), string(body), dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	if w.Code != http.StatusOK {
		return nil, fmt.Errorf("actual native revision PATCH=%d", w.Code)
	}
	return f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: document.ID, OrgID: f.org})
}

func TestStaleRestoreLeavesEvidenceUntouchedE2E(t *testing.T) {
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, native)
	f := native.f
	ctx, pool, q, server, org, user := f.ctx, f.pool, f.q, f.s, f.org, f.user.ID
	doc, err := nativeRevisionCreateE2E(t, f, "Restore", json.RawMessage(`{"version":1,"blocks":[]}`), json.RawMessage(`{"value":"historical"}`))
	if err != nil {
		t.Fatal(err)
	}
	server.Versions = versions.New(q)
	doc, err = nativeRevisionEditE2E(t, f, doc, doc.BlocksJson, doc.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	target, err := q.GetLatestDocumentVersion(ctx, doc.ID)
	if err != nil || target == nil || string(target.BlockTreeJson) != string(doc.BlocksJson) || string(target.VariablesJson) != string(doc.VariablesJson) {
		t.Fatal("actual native historical target differs from current draft", err)
	}
	old := toDocumentResponse(doc).UpdatedAt
	current, err := nativeRevisionEditE2E(t, f, doc, doc.BlocksJson, json.RawMessage(`{"value":"current"}`))
	if err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		var v, e int
		if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1), (SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	beforeV, beforeE := counts()
	ctx = context.WithValue(ctx, auth.UserIDKey, user)
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	liveUser, err := q.GetUser(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, server, user, liveUser.SessionGeneration, time.Hour)
	router := chi.NewRouter()
	router.Post("/{id}/versions/{n}/restore", server.handleRestoreVersion)
	call := func(stamp string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]string{"expected_updated_at": stamp})
		req := httptest.NewRequest(http.MethodPost, "/"+doc.ID.String()+"/versions/"+strconv.Itoa(int(target.VersionNo))+"/restore", strings.NewReader(string(raw))).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := call(old); w.Code != 412 {
		t.Fatalf("stale restore: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE := counts()
	if afterV != beforeV || afterE != beforeE {
		t.Fatal("stale restore created evidence")
	}
	unchanged, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged.VariablesJson) != string(current.VariablesJson) || !unchanged.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
		t.Fatal("stale restore mutated document")
	}
	if w := call(toDocumentResponse(current).UpdatedAt); w.Code != 200 {
		t.Fatalf("fresh restore: %d %s", w.Code, w.Body.String())
	}
	restored, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if string(restored.VariablesJson) != string(target.VariablesJson) {
		t.Fatal("fresh restore did not restore target")
	}
	afterV, afterE = counts()
	if afterV <= beforeV || afterE <= beforeE {
		t.Fatal("fresh restore missing version or audit")
	}
}

func TestStaleBlockReplacementLeavesEvidenceUntouchedE2E(t *testing.T) {
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, native)
	f := native.f
	ctx, pool, q, server, org, user := f.ctx, f.pool, f.q, f.s, f.org, f.user.ID
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := nativeRevisionCreateE2E(t, f, "Blocks", original, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	current, err := nativeRevisionEditE2E(t, f, doc, json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), doc.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		var v, e int
		if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	beforeV, beforeE := counts()
	ctx = context.WithValue(ctx, auth.UserIDKey, user)
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	liveUser, err := q.GetUser(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, server, user, liveUser.SessionGeneration, time.Hour)
	router := chi.NewRouter()
	router.Patch("/{id}/blocks/{bid}", server.handleUpdateBlock)
	call := func(stamp string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"expected_updated_at": stamp, "block": map[string]string{"id": "p", "type": "paragraph", "text": "replacement"}})
		req := httptest.NewRequest(http.MethodPatch, "/"+doc.ID.String()+"/blocks/p", strings.NewReader(string(raw))).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := call(toDocumentResponse(doc).UpdatedAt); w.Code != 412 {
		t.Fatalf("stale block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE := counts()
	if beforeV != afterV || beforeE != afterE {
		t.Fatal("stale block created evidence")
	}
	unchanged, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged.BlocksJson) != string(current.BlocksJson) || !unchanged.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
		t.Fatal("stale block changed row")
	}
	if w := call(toDocumentResponse(current).UpdatedAt); w.Code != 200 {
		t.Fatalf("fresh block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE = counts()
	if afterV <= beforeV || afterE <= beforeE {
		t.Fatal("fresh block missing evidence")
	}
}

func TestStaleImportReplacementLeavesEvidenceUntouchedE2E(t *testing.T) {
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, native)
	f := native.f
	ctx, pool, q, server, org, user := f.ctx, f.pool, f.q, f.s, f.org, f.user.ID
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := nativeRevisionCreateE2E(t, f, "Blocks", original, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	current, err := nativeRevisionEditE2E(t, f, doc, json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), doc.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		var v, e int
		if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	beforeV, beforeE := counts()
	ctx = context.WithValue(ctx, auth.UserIDKey, user)
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	liveUser, err := q.GetUser(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, server, user, liveUser.SessionGeneration, time.Hour)
	router := chi.NewRouter()
	router.Post("/{id}/import-html", server.handleImportHTML)
	router.Post("/{id}/import-md", server.handleImportMarkdown)
	call := func(path, key, content, stamp string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"expected_updated_at": stamp, key: content})
		req := httptest.NewRequest(http.MethodPost, "/"+doc.ID.String()+path, strings.NewReader(string(raw))).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	for _, input := range []struct{ path, key, content string }{{"/import-html", "html", "<p>replacement</p>"}, {"/import-md", "markdown", "replacement"}} {
		if w := call(input.path, input.key, input.content, toDocumentResponse(doc).UpdatedAt); w.Code != 412 {
			t.Fatalf("stale block: %d %s", w.Code, w.Body.String())
		}
		afterV, afterE := counts()
		if beforeV != afterV || beforeE != afterE {
			t.Fatal("stale block created evidence")
		}
		unchanged, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
		if err != nil {
			t.Fatal(err)
		}
		if string(unchanged.BlocksJson) != string(current.BlocksJson) || !unchanged.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
			t.Fatal("stale import changed row")
		}
	}
	if w := call("/import-html", "html", "<p>replacement</p>", toDocumentResponse(current).UpdatedAt); w.Code != 200 {
		t.Fatalf("fresh block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE := counts()
	if afterV <= beforeV || afterE <= beforeE {
		t.Fatal("fresh block missing evidence")
	}
}

func TestStaleReorderLeavesEvidenceUntouchedE2E(t *testing.T) {
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, native)
	f := native.f
	ctx, pool, q, server, org, user := f.ctx, f.pool, f.q, f.s, f.org, f.user.ID
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"},{"id":"q","type":"paragraph","text":"second"}]}`)
	doc, err := nativeRevisionCreateE2E(t, f, "Blocks", original, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	current, err := nativeRevisionEditE2E(t, f, doc, json.RawMessage(`{"version":1,"blocks":[{"id":"q","type":"paragraph","text":"second"},{"id":"p","type":"paragraph","text":"original"}]}`), doc.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		var v, e int
		if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	beforeV, beforeE := counts()
	ctx = context.WithValue(ctx, auth.UserIDKey, user)
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	liveUser, err := q.GetUser(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, server, user, liveUser.SessionGeneration, time.Hour)
	router := chi.NewRouter()
	router.Post("/{id}/blocks/reorder", server.handleReorderBlocks)
	call := func(stamp string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"expected_updated_at": stamp, "block_ids": []string{"p", "q"}})
		req := httptest.NewRequest(http.MethodPost, "/"+doc.ID.String()+"/blocks/reorder", strings.NewReader(string(raw))).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := call(toDocumentResponse(doc).UpdatedAt); w.Code != 412 {
		t.Fatalf("stale block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE := counts()
	if beforeV != afterV || beforeE != afterE {
		t.Fatal("stale block created evidence")
	}
	unchanged, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged.BlocksJson) != string(current.BlocksJson) || !unchanged.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
		t.Fatal("stale block changed row")
	}
	if w := call(toDocumentResponse(current).UpdatedAt); w.Code != 200 {
		t.Fatalf("fresh block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE = counts()
	if afterV <= beforeV || afterE <= beforeE {
		t.Fatal("fresh block missing evidence")
	}
}

func TestStaleDeleteLeavesEvidenceUntouchedE2E(t *testing.T) {
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, native)
	f := native.f
	ctx, pool, q, server, org, user := f.ctx, f.pool, f.q, f.s, f.org, f.user.ID
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := nativeRevisionCreateE2E(t, f, "Blocks", original, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	current, err := nativeRevisionEditE2E(t, f, doc, json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), doc.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		var v, e int
		if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	beforeV, beforeE := counts()
	ctx = context.WithValue(ctx, auth.UserIDKey, user)
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	liveUser, err := q.GetUser(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, server, user, liveUser.SessionGeneration, time.Hour)
	router := chi.NewRouter()
	router.Delete("/{id}/blocks/{bid}", server.handleDeleteBlock)
	call := func(stamp string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"expected_updated_at": stamp})
		req := httptest.NewRequest(http.MethodDelete, "/"+doc.ID.String()+"/blocks/p", strings.NewReader(string(raw))).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := call(toDocumentResponse(doc).UpdatedAt); w.Code != 412 {
		t.Fatalf("stale block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE := counts()
	if beforeV != afterV || beforeE != afterE {
		t.Fatal("stale block created evidence")
	}
	unchanged, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged.BlocksJson) != string(current.BlocksJson) || !unchanged.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
		t.Fatal("stale block changed row")
	}
	if w := call(toDocumentResponse(current).UpdatedAt); w.Code != 200 {
		t.Fatalf("fresh block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE = counts()
	if afterV <= beforeV || afterE <= beforeE {
		t.Fatal("fresh block missing evidence")
	}
	deleted, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	var tree struct {
		Blocks []json.RawMessage `json:"blocks"`
	}
	if err := json.Unmarshal(deleted.BlocksJson, &tree); err != nil {
		t.Fatal(err)
	}
	if len(tree.Blocks) != 0 {
		t.Fatal("fresh deletion did not remove reviewed block")
	}

}

func TestAppendRetryDoesNotDuplicateGeneratedBlockE2E(t *testing.T) {
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, native)
	f := native.f
	ctx, pool, q, server, org, user := f.ctx, f.pool, f.q, f.s, f.org, f.user.ID
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := nativeRevisionCreateE2E(t, f, "Blocks", original, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	current, err := nativeRevisionEditE2E(t, f, doc, json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), doc.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		var v, e int
		if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	beforeV, beforeE := counts()
	ctx = context.WithValue(ctx, auth.UserIDKey, user)
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	liveUser, err := q.GetUser(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, server, user, liveUser.SessionGeneration, time.Hour)
	router := chi.NewRouter()
	router.Post("/{id}/blocks", server.handleAppendBlock)
	call := func(stamp string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"expected_updated_at": stamp, "block": map[string]string{"type": "paragraph", "text": "replacement"}})
		req := httptest.NewRequest(http.MethodPost, "/"+doc.ID.String()+"/blocks", strings.NewReader(string(raw))).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	if w := call(toDocumentResponse(doc).UpdatedAt); w.Code != 412 {
		t.Fatalf("stale block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE := counts()
	if beforeV != afterV || beforeE != afterE {
		t.Fatal("stale block created evidence")
	}
	unchanged, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged.BlocksJson) != string(current.BlocksJson) || !unchanged.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
		t.Fatal("stale block changed row")
	}
	if w := call(toDocumentResponse(current).UpdatedAt); w.Code != 200 {
		t.Fatalf("fresh block: %d %s", w.Code, w.Body.String())
	}
	afterV, afterE = counts()
	if afterV <= beforeV || afterE <= beforeE {
		t.Fatal("fresh block missing evidence")
	}
	if w := call(toDocumentResponse(current).UpdatedAt); w.Code != 412 {
		t.Fatalf("repeat append: %d %s", w.Code, w.Body.String())
	}
	retryV, retryE := counts()
	if retryV != afterV || retryE != afterE {
		t.Fatal("retry created evidence")
	}
	final, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	var tree struct {
		Blocks []struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal(final.BlocksJson, &tree); err != nil {
		t.Fatal(err)
	}
	if len(tree.Blocks) != 2 || tree.Blocks[1].ID == "" || tree.Blocks[1].Text != "replacement" {
		t.Fatalf("append content: %s", final.BlocksJson)
	}

}
