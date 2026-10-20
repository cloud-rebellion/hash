//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// A genuine post-commit view hook retains THIS operation's audit payload after
// its physical SQL retires. Successful view/SQL completion must preserve the
// original asynchronous hook contract while retaining its admission and debt.
// A known live hook is not physical/fence uncertainty; the separate foreign
// reader test covers isolation from unrelated unresolved ownership.
func TestOwnedSignerViewRetainsItsOwnAuditConsumerCleanupE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	party := parties[0]
	rc := q.lookupV1(t, party.Token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
	if err != nil {
		t.Fatal("genuine current notice unavailable")
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal("genuine current notice evidence unavailable")
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal("genuine notice read did not close")
	}
	q.assertObserversOnlyV1(t)
	factory := q.runtime.SessionsV1()

	started := make(chan audit.PendingEvent, 1)
	release := make(chan struct{})
	finished := make(chan struct{})
	var releaseOnce, hookOnce sync.Once
	attempted, joinAttempted := false, false
	join := func() bool {
		t.Helper()
		if joinAttempted {
			return factory.PendingV1().HTMLAdmissions == 0
		}
		joinAttempted = true
		releaseOnce.Do(func() { close(release) })
		if !attempted {
			return true
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-finished:
		case <-cleanup.Done():
			t.Error("actual view event hook did not join")
			return false
		}
		// Hook return precedes the logger wrapper's actual lastUse finisher.
		// Reconcile and observe the original admission under this same budget;
		// nil global cleanup alone never proves pending HTML consumer retirement.
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			err := factory.ReconcileCleanupV1(cleanup)
			if err != nil && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
				t.Error("actual view admission cleanup returned an unexpected class")
				return false
			}
			if factory.PendingV1().HTMLAdmissions == 0 {
				return true
			}
			select {
			case <-ticker.C:
			case <-cleanup.Done():
				t.Error("actual view admission did not retire after original hook last use")
				return false
			}
		}
	}
	// Registered before any request/fatal path can leave the real hook retained.
	t.Cleanup(func() { _ = join() })
	f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		if e.Kind != audit.KindDocumentViewed || e.DocumentID == nil || *e.DocumentID != doc.ID || e.RecipientID == nil || *e.RecipientID != party.RecipientID {
			return
		}
		hookOnce.Do(func() {
			defer close(finished)
			started <- audit.PendingEvent{ID: id, Entry: e}
			// Deliberately retain actual payload past hook cancellation. Only
			// this original callback's return establishes its last use.
			<-release
		})
	})
	var initial int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM events WHERE document_id=$1 AND recipient_id=$2 AND kind='document.viewed'", doc.ID, party.RecipientID).Scan(&initial); err != nil || initial != 0 {
		t.Fatal("target already has viewed evidence or bounded witness failed")
	} //nolint:rawsql -- actual fresh target event witness only

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sign/"+party.Token+"/view", strings.NewReader("{}")).WithContext(f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
	attempted = true
	f.s.Routes().ServeHTTP(w, r)
	var event audit.PendingEvent
	observe, stop := context.WithTimeout(f.ctx, 5*time.Second)
	select {
	case event = <-started:
	case <-observe.Done():
		stop()
		t.Fatal("actual post-commit view hook never started")
	}
	stop()
	if event.ID == uuid.Nil || event.Entry.OrgID != f.org || event.Entry.DocumentID == nil || *event.Entry.DocumentID != doc.ID || event.Entry.RecipientID == nil || *event.Entry.RecipientID != party.RecipientID || event.Entry.Kind != audit.KindDocumentViewed {
		t.Fatal("actual post-commit view event identity differs")
	}
	if w.Code != http.StatusOK {
		t.Errorf("view must preserve acknowledged completion with its known asynchronous hook retained: status=%d", w.Code)
	}

	row, err := f.q.GetEventByID(f.ctx, event.ID)
	if err != nil {
		t.Fatal("genuine freshly committed view event unavailable")
	}
	recomputed, err := audit.RecomputeEventRowHash(row)
	if err != nil || !bytes.Equal(recomputed, row.RowHash) {
		t.Fatal("genuine freshly committed view event hash differs")
	}
	hookRaw, err := json.Marshal(event.Entry.Payload)
	if err != nil || !bytes.Equal(hookRaw, row.PayloadHashed) {
		t.Fatal("actual hook payload differs from freshly hashed view event")
	}
	var events, measured int
	var wire int64
	var exact bool
	var status string
	err = f.pool.QueryRow(f.ctx, "SELECT count(*),count(*) FILTER(WHERE m.event_id=e.id AND m.org_id=e.org_id AND m.document_id=e.document_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer),COALESCE(sum(m.payload_wire_bytes),0)::bigint,COALESCE(bool_and(e.id=$5 AND e.recipient_id=$3 AND e.payload_json->>'notice_digest'=$4),false),(SELECT status FROM recipients WHERE id=$3 AND document_id=$1) FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.viewed'", doc.ID, f.org, party.RecipientID, evidence.Digest, event.ID).Scan(&events, &measured, &wire, &exact, &status) //nolint:rawsql -- exact native view/M94/recipient witness only; never insert or repair
	if err != nil || events != 1 || measured != 1 || wire < 2 || !exact || status != "viewed" {
		t.Fatal("genuine native view did not commit its one exact measured event")
	}

	// HTTP lease last use can leave an already-empty read admission registered.
	// Run the genuine sweep before taking the quiescent consumer observation;
	// both this sweep and the stability sweep below share the original2s budget.
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := factory.ReconcileCleanupV1(cleanup); err != nil && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		t.Fatal("actual post-response cleanup returned an unexpected class")
	}
	before := q.snapshotV1(t)
	pending := factory.PendingV1()
	// Lower bounds derive from actual fresh server wire and independently
	// verified hashed/hook encodings; they are reservations, not heap/RSS.
	if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 1 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.ObserverSessions != 2 || before.Global.SQLSessions != 2 || before.Organisation.SQLSessions != 1 || before.GlobalGrants != 3 || before.OrganisationGrants != 2 || before.Global.ParentBytes < wire || before.Global.ParentBytes < int64(len(row.PayloadHashed)) || before.Global.ParentBytes < int64(len(hookRaw)) || before.Global.DBStagingBytes < wire || before.Global.ParentBytes != before.Organisation.ParentBytes || before.Global.DBStagingBytes != before.Organisation.DBStagingBytes {
		t.Fatalf("own actual audit consumer debt was lost or physical SQL did not retire: pending=%+v snapshot=%+v wire=%d hashed=%d hook=%d", pending, before, wire, len(row.PayloadHashed), len(hookRaw))
	}
	reconcileErr := factory.ReconcileCleanupV1(cleanup)
	cancel()
	// The global sweep historically may return nil while a known consumer is
	// pending. Its return value is not the reservation-retirement witness.
	if reconcileErr != nil && !errors.Is(reconcileErr, pdfadmission.ErrApplicationSessionUnknownV1) {
		t.Fatal("own actual audit consumer cleanup returned an unexpected class")
	}
	if q.snapshotV1(t) != before || factory.PendingV1().HTMLAdmissions != 1 {
		t.Fatal("global cleanup credited the retained original view consumer")
	}
	t.Logf("own view status=%d committed=1 measured=1 status=viewed; physical SQL retired while its original asynchronous audit consumer remains charged", w.Code)
	// Drop test-oracle references to the hook's actual payload before release.
	event = audit.PendingEvent{}
	hookRaw = nil
	if !join() {
		t.Fatal("actual view hook and admission did not join within original cleanup budget")
	}
	q.assertObserversOnlyV1(t)
	t.Log("original view hook last use and actual admission/registry cleanup joined; only process and tenant observer debt remains")
}
