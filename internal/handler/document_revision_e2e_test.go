// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestDocumentRevisionConcurrentSaveE2E(t *testing.T) {
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, native)
	f := native.f
	ctx, pool, q, server, org, user := f.ctx, f.pool, f.q, f.s, f.org, f.user.ID
	doc, err := nativeRevisionCreateE2E(t, f, "Original", json.RawMessage(`{"version":1,"blocks":[]}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the same signed-cookie admission and retained transaction
	// authority as the real document route, including the concurrent writers.
	cookie := dsrSessionCookieE2E(t, server, user, 0, time.Hour)
	call := func(body string) *httptest.ResponseRecorder {
		return submitSessionOperationE2E(server, http.MethodPatch, "/api/v1/documents/"+doc.ID.String(), body, cookie)
	}
	if w := call(`{"name":"missing"}`); w.Code != 428 {
		t.Fatalf("missing precondition: %d %s", w.Code, w.Body.String())
	}
	expected := toDocumentResponse(doc).UpdatedAt
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"First", "Second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			<-start
			raw, _ := json.Marshal(map[string]string{"name": name, "expected_updated_at": expected})
			results <- call(string(raw))
		}(name)
	}
	close(start)
	wg.Wait()
	close(results)
	counts := map[int]int{}
	var winner documentResponse
	for w := range results {
		counts[w.Code]++
		if w.Code == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &winner); err != nil {
				t.Fatal(err)
			}
		} else if w.Code != 412 {
			t.Fatalf("unexpected: %d %s", w.Code, w.Body.String())
		}
	}
	if counts[200] != 1 || counts[412] != 1 {
		t.Fatalf("outcomes %v", counts)
	}
	current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if current.Name != winner.Name || !current.UpdatedAt.Time.After(doc.UpdatedAt.Time) {
		t.Fatal("winner not authoritative or clock failed")
	}
	// Start a transaction first, let a newer transaction commit, then write
	// from the older transaction: transaction-start now() must not regress clock.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var started time.Time
	if err := tx.QueryRow(ctx, "SELECT now()").Scan(&started); err != nil {
		t.Fatal(err)
	}
	var newer time.Time
	if err := pool.QueryRow(ctx, "UPDATE documents SET name='Newer' WHERE id=$1 RETURNING updated_at", doc.ID).Scan(&newer); err != nil {
		t.Fatal(err)
	}
	var final time.Time
	if err := tx.QueryRow(ctx, "UPDATE documents SET name='Older transaction' WHERE id=$1 RETURNING updated_at", doc.ID).Scan(&final); err != nil {
		t.Fatal(err)
	}
	if !final.After(newer) || !final.After(started) {
		t.Fatal("old transaction regressed document clock")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
