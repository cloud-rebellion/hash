//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Retain a real consumer on a separate reader after its actual SQL retires.
// Factory cleanup must retain that debt, but an independent view must report
// its own outcome. This controlled schedule does not diagnose browser153e.
func TestOwnedSignerViewDoesNotInheritUnrelatedReaderCleanupE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	party := parties[0]
	rc := q.lookupV1(t, party.Token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	factory := q.runtime.SessionsV1()
	scope, err := factory.ProbeSignerScopeV1(f.ctx, auth.HashMagicToken(party.Token))
	var reader *pdfadmission.ApplicationSignerReaderV1
	var retained *pdfadmission.ApplicationSignerViewRequestV1
	released := false
	release := func() {
		t.Helper()
		if released {
			return
		}
		if retained != nil {
			retained.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if reader != nil {
			if err := reader.CloseV1(cleanup); err != nil {
				t.Error("actual sibling reader did not retire after last use", err)
			}
		}
		if scope != nil {
			scope.CloseConsumerV1()
		}
		if err := factory.ReconcileCleanupV1(cleanup); err != nil {
			t.Error("actual sibling ownership did not reconcile", err)
		}
		released = true
	}
	t.Cleanup(release)
	if err != nil {
		t.Fatal(err)
	}
	reader, err = factory.NewSignerReaderV1(f.ctx, scope, pdfadmission.SignerReadActiveV1)
	if err != nil {
		t.Fatal(err)
	}
	err = reader.WithModelsV1(f.ctx, func(a pdfadmission.ApplicationSignerReadAccessV1) error {
		now := time.Now()
		if !a.ActiveCeremony || (a.DocumentExpiresAt.Valid && !now.Before(a.DocumentExpiresAt.Time)) || (a.RecipientExpiresAt.Valid && !now.Before(a.RecipientExpiresAt.Time)) {
			return fmt.Errorf("genuine sibling access is no longer active")
		}
		return nil
	}, func(_ context.Context, models *pdfadmission.ApplicationSignerReadModelsV1) error {
		if models == nil || models.Document == nil || models.Recipient == nil || models.Document.ID != doc.ID || models.Document.OrgID != f.org || models.Recipient.ID != party.RecipientID || models.Recipient.DocumentID != doc.ID {
			return fmt.Errorf("genuine sibling scope differs")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = reader.CommitReadV1(f.ctx); err != nil {
		t.Fatal(err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = reader.CloseSQLV1(cleanup)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	retained, err = factory.NewSignerViewRequestV1(f.ctx, reader, "127.0.0.1", "Synthetic retained native view consumer", evidence)
	if err != nil {
		t.Fatal(err)
	}
	before := q.snapshotV1(t)
	cleanup, stop = context.WithTimeout(context.Background(), 5*time.Second)
	err = reader.CloseV1(cleanup)
	stop()
	if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || q.snapshotV1(t) != before {
		t.Fatal("genuine retained reader debt was not preserved", err)
	}
	pending := factory.PendingV1()
	if pending.SignerReaders != 1 || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 2 || before.Organisation.SQLSessions != 1 || before.Global.SQLSessions != 2 || before.Global.ParentBytes == 0 {
		t.Fatal("retained sibling is not a physical-SQL-retired body consumer", pending, before)
	}
	var initial int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer FROM events WHERE document_id=$1 AND recipient_id=$2 AND kind='document.viewed'`, doc.ID, party.RecipientID).Scan(&initial); err != nil || initial != 0 {
		t.Fatal("target already has viewed evidence", initial, err)
	} //nolint:rawsql -- actual target event witness
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/sign/"+party.Token+"/view", strings.NewReader(`{}`)).WithContext(f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
	f.s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("independent view must report its own completed outcome: status=%d", w.Code)
	}
	var events, measured int
	var status string
	var exact bool
	err = f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE m.event_id=e.id AND m.org_id=e.org_id AND m.document_id=e.document_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer),COALESCE(bool_and(e.recipient_id=$3 AND e.payload_json->>'notice_digest'=$4),false),(SELECT status FROM recipients WHERE id=$3 AND document_id=$1) FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.viewed'`, doc.ID, f.org, party.RecipientID, evidence.Digest).Scan(&events, &measured, &exact, &status) //nolint:rawsql -- actual committed independent view/M94/recipient oracle
	if err != nil || events != 1 || measured != 1 || !exact || status != "viewed" {
		t.Fatal("independent native view did not commit its exact event", events, measured, exact, status, err)
	}
	cleanup, stop = context.WithTimeout(context.Background(), 5*time.Second)
	err = factory.ReconcileCleanupV1(cleanup)
	stop()
	if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || q.snapshotV1(t) != before || factory.PendingV1().SignerReaders != 1 {
		t.Fatal("unrelated retained debt was swallowed or credited", err)
	}
	t.Log("independent view committed: viewed=1 measured=1 status=viewed; unrelated consumer remains charged and unresolved")
	release()
	q.assertObserversOnlyV1(t)
	t.Log("genuine sibling request last use, reader/scope cleanup and observer-only drain joined")
}
