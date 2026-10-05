// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"context"
	"encoding/json"
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

func TestStaleRestoreLeavesEvidenceUntouchedE2E(t *testing.T) {
	ctx, pool, q, server, org, user := setupDSRE2E(t)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "Restore", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{"value":"historical"}`)})
	if err != nil {
		t.Fatal(err)
	}
	target, err := versions.New(q).Snapshot(ctx, versions.SnapshotInput{DocumentID: doc.ID, OrgID: org, Name: doc.Name, SourceKind: doc.SourceKind, BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &user, Via: versions.ViaHuman})
	if err != nil {
		t.Fatal(err)
	}
	old := toDocumentResponse(doc).UpdatedAt
	current, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: doc.ID, OrgID: org, BlocksJson: doc.BlocksJson, VariablesJson: json.RawMessage(`{"value":"current"}`)})
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
	ctx, pool, q, server, org, user := setupDSRE2E(t)
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "Blocks", BlocksJson: original, VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	current, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: doc.ID, OrgID: org, BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), VariablesJson: doc.VariablesJson})
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
	ctx, pool, q, server, org, user := setupDSRE2E(t)
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "Blocks", BlocksJson: original, VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	current, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: doc.ID, OrgID: org, BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), VariablesJson: doc.VariablesJson})
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
	ctx, pool, q, server, org, user := setupDSRE2E(t)
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"},{"id":"q","type":"paragraph","text":"second"}]}`)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "Blocks", BlocksJson: original, VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	current, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: doc.ID, OrgID: org, BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"q","type":"paragraph","text":"second"},{"id":"p","type":"paragraph","text":"original"}]}`), VariablesJson: doc.VariablesJson})
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
	ctx, pool, q, server, org, user := setupDSRE2E(t)
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "Blocks", BlocksJson: original, VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	current, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: doc.ID, OrgID: org, BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), VariablesJson: doc.VariablesJson})
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
	ctx, pool, q, server, org, user := setupDSRE2E(t)
	server.Versions = versions.New(q)
	original := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "Blocks", BlocksJson: original, VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	current, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: doc.ID, OrgID: org, BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"other client"}]}`), VariablesJson: doc.VariablesJson})
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
