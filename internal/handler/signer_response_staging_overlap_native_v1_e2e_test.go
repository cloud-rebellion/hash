//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
)

// A real route delivers a separately serialized JSON body after the native SQL
// producer has committed and joined. The response keeps its actual row/JSON
// grant through the final Write; the unrelated fixed producer-header class must
// have ended. This is a lifetime assertion, not a new application byte quota.
func TestOwnedCommentJSONOutlivesRetiredProducerE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, _ := q.createSentV1(t)
	ownedHistoricalCommentRows166V1(t, q, doc)
	ctx, cancel := context.WithCancel(q.f.ctx)
	w := &ownedCommentPageWriter166V1{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{}), life: q.f.ctx}
	done := make(chan struct{})
	var release sync.Once
	defer func() {
		release.Do(func() { close(w.release) })
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("actual comment response did not join")
		}
	}()
	r := ownedCommentPageRequest166V1(q, ctx, doc, "", "")
	go func() { defer close(done); q.f.s.Routes().ServeHTTP(w, r) }()
	select {
	case <-w.entered:
	case <-done:
		t.Fatal("actual comment response ended before held Write")
	case <-time.After(5 * time.Second):
		t.Fatal("actual comment response never reached held Write")
	}
	if w.Code != http.StatusOK {
		t.Fatal("held comment Write was not a successful response", w.Code)
	}
	pending := q.runtime.SessionsV1().PendingV1()
	snapshot, err := q.runtime.SnapshotV1(q.f.org)
	want := pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 1, HTMLAdmissions: 1, HTMLInputProducers: 1}
	if err != nil || pending != want || snapshot.Organisation.ParentBytes < 32<<20 || snapshot.Global.SQLSessions != 1 || snapshot.Organisation.SQLSessions != 1 || snapshot.Organisation.DBStagingBytes < 16*54679 {
		t.Fatal("actual JSON lost its paid response ownership", pending, err)
	}
	// The original native producer has a fixed32MiB header loan. The retained
	// JSON uses the independently admitted body cost (fixed controls+16*text),
	// well below that floor for this exact54679B page. Keep the observation until
	// after actual Write, last consumer and physical cleanup have all completed.
	retainedProducer := snapshot.Organisation.DBStagingBytes >= 32<<20
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
	_ = q.runtime.ReconcileCleanupV1(cleanup)
	stop()
	after, afterErr := q.runtime.SnapshotV1(q.f.org)
	if afterErr != nil || after != snapshot || q.runtime.SessionsV1().PendingV1() != pending {
		t.Fatal("cancellation credited a still-writing JSON response", afterErr)
	}
	release.Do(func() { close(w.release) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("actual comment response did not join after Write release")
	}
	if w.timedOut.Load() {
		t.Fatal("writer used timeout as consumer release")
	}
	var page pdfadmission.CommentPageResponseV1
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Comments) != 50 {
		t.Fatal("actual comment response lost bounded JSON")
	}
	textBytes := 0
	for _, row := range page.Comments {
		textBytes += len(row.AuthorName) + len(row.AuthorSide) + len(row.Body)
	}
	if textBytes != 54679 {
		t.Fatal("exact historical row fixture changed", textBytes)
	}
	q.reconcileV1(t)
	drained := q.runtime.SessionsV1().PendingV1()
	observed, err := q.runtime.SnapshotV1(q.f.org)
	if err != nil || drained != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 1}) || observed.Global != (workguard.VectorV1{SQLSessions: 1}) || observed.GlobalGrants != 1 || observed.Organisation != (workguard.VectorV1{SQLSessions: 1}) || observed.OrganisationGrants != 1 {
		t.Fatal("last JSON consumer failed to drain genuine native debt", drained, observed, err)
	}
	if retainedProducer {
		t.Errorf("completed comment producer retained its fixed header during actual Write: db_staging=%d text_bytes=%d producer_header_floor=%d", snapshot.Organisation.DBStagingBytes, textBytes, 32<<20)
	}
}
