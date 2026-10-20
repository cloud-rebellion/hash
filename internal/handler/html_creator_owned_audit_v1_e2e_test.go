//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Genuine target birth uses the already-qualified real schema3 template,
// approval, worker and native writer. Synthetic renderer/S3/retention boundaries
// are unchanged. No event cache is inserted/measured by this test.
func TestOwnedHTMLCreatorAuditCacheAndHookLifetimeE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	started := make(chan audit.PendingEvent, 1)
	release := make(chan struct{})
	finished := make(chan struct{})
	var once sync.Once
	f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		if e.Kind != audit.KindDocumentCreated || e.Payload["authoring_kind"] != "html" {
			return
		}
		defer close(finished)
		started <- audit.PendingEvent{ID: id, Entry: e}
		<-release
	})
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-finished:
		case <-ctx.Done():
			t.Error("actual creator event hook did not join")
		}
	})
	doc := createHTMLContractDocumentE2E(t, f, q.template, q.cookie)
	var event audit.PendingEvent
	select {
	case event = <-started:
	case <-f.ctx.Done():
		t.Fatal("actual post-commit creator hook never started")
	}
	if event.ID == uuid.Nil || event.Entry.DocumentID == nil || *event.Entry.DocumentID != doc.ID || event.Entry.OrgID != f.org || event.Entry.ActorUserID == nil || *event.Entry.ActorUserID != f.user.ID {
		t.Fatal("actual creator event identity changed")
	}
	// Read only the finite freshly-created event; actual server-derived wire and
	// row hash prove the producer selected the exact inserted event, not a report.
	row, err := f.q.GetEventByID(f.ctx, event.ID)
	if err != nil {
		t.Fatal("read genuine fresh event", err)
	}
	recomputed, err := audit.RecomputeEventRowHash(row)
	if err != nil || !bytes.Equal(recomputed, row.RowHash) {
		t.Fatal("new owned producer changed original audit hash semantics", err)
	}
	var count, wire int64
	var actual bool
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::bigint,COALESCE(sum(s.payload_wire_bytes),0)::bigint,COALESCE(bool_and(s.payload_wire_bytes=octet_length(e.payload_json::text) AND s.measurement_server_version_num=current_setting('server_version_num')::integer AND s.measured_at<=clock_timestamp()),false) FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 s ON s.event_id=e.id AND s.document_id=e.document_id AND s.org_id=e.org_id WHERE e.id=$1 AND e.document_id=$2 AND e.org_id=$3", event.ID, doc.ID, f.org).Scan(&count, &wire, &actual); err != nil || count != 1 || wire < 2 || !actual {
		t.Fatal("actual native creator did not derive exactly its genuine new event cache", err)
	} //nolint:rawsql -- bounded fresh event cache witness only
	hookRaw, err := json.Marshal(event.Entry.Payload)
	if err != nil || !bytes.Equal(hookRaw, row.PayloadHashed) {
		t.Fatal("concrete hook payload differs from exact originally hashed event", err)
	}
	// A real hook ignoring its timeout retains the payload. Ending the HTTP
	// producer/response and original SQL session must not refund its last use. This creator-only
	// journey legitimately starts one tenant observer, with no global token probe.
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	reconcileErr := q.runtime.ReconcileCleanupV1(cleanup)
	stop()
	if reconcileErr != nil && !errors.Is(reconcileErr, pdfadmission.ErrApplicationSessionUnknownV1) {
		t.Fatal(reconcileErr)
	}
	pending := q.runtime.SessionsV1().PendingV1()
	snap := q.snapshotV1(t)
	// Independent source-volume lower bounds use the genuine server wire/cache
	// and the already-verified exact hashed/hook encodings. These are reservation
	// assertions, not heap/RSS measurements or a copy of the private allocator.
	// The real hook must retain positive source debt after SQL/HTTP last use;
	// fixed native control/type costs may change without restoring a 32MiB fiction.
	if pending.WorkSessions != 0 || pending.HTMLAdmissions != 1 || pending.ObserverSessions != 1 || snap.Global.ParentBytes < wire || snap.Global.ParentBytes < int64(len(row.PayloadHashed)) || snap.Global.ParentBytes < int64(len(hookRaw)) || snap.Global.DBStagingBytes < wire || snap.Global.SQLSessions != 1 || snap.GlobalGrants != 2 || snap.Global.ParentBytes != snap.Organisation.ParentBytes || snap.Global.DBStagingBytes != snap.Organisation.DBStagingBytes {
		t.Fatalf("actual physical-first event payload lifetime not retained: pending=%+v snapshot=%+v", pending, snap)
	}
	once.Do(func() { close(release) })
	select {
	case <-finished:
	case <-f.ctx.Done():
		t.Fatal("actual event hook did not finish")
	}
	q.reconcileV1(t)
	pending = q.runtime.SessionsV1().PendingV1()
	after := q.snapshotV1(t)
	if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.ObserverSessions != 1 || after.Global != (workguard.VectorV1{SQLSessions: 1}) || after.GlobalGrants != 1 || after.Organisation != (workguard.VectorV1{SQLSessions: 1}) || after.OrganisationGrants != 1 {
		t.Fatal("event consumer/session/registry conjunction leaked or credited actual tenant observer debt", pending, after)
	}
}
