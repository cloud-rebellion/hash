//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bright-interaction/hash/internal/amendmentauthoring"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/google/uuid"
)

// Real native result ownership/serialization followed by immediate ordinary
// HTTP replay, using the unchanged allocated budget and actual original cookie.
// Synthetic provider peers qualify bindings/transactions, not real delivery.
func TestLaterNoticeResultRetiresOnlyAfterSerializationThenImmediateReplay484E2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	// Retire genuinely finished SETUP consumers once, before this target starts.
	// There is deliberately no manual/global reconciliation after target Close
	// and before the immediate replay that exposed the original qualification bug.
	f.q.assertObserversOnlyV1(t)
	baseline := f.q.snapshotV1(t)
	var err error
	f.q.f.s.NoticeAccess, err = f.q.runtime.NewLaterAmendmentNoticeAccessV1(f.q.f.s.Storage, f.q.f.s.Cookies, f.q.f.s.PublicURL)
	if err != nil {
		t.Fatal(err)
	}
	candidate := packageLatest223(t, f.q, f.candidate.ID)
	in := amendments.IssueNoticeV1{RequestID: uuid.New(), ExpectedHeadRevision: f.record.Revision, ExpectedDocumentUpdatedAt: candidate.UpdatedAt.Time, Subject: "Synthetic last-use notice", Text: "Read the exact later files. Reading and queueing do not imply acceptance.", RecipientEmails: []string{"legal@example.test"}, Reviewed: true}
	credential := auth.SessionPayload{UserID: f.q.f.user.ID, Generation: f.q.f.user.SessionGeneration}
	actor := authoring.Actor{OrgID: f.q.f.org, UserID: f.q.f.user.ID, Authorize: auth.SessionTransactionAuthorization(f.q.f.s.Cookies, f.q.cookie, credential, f.q.f.org)}
	out, err := amendmentauthoring.IssueNoticeV1(f.q.f.ctx, amendmentauthoring.DependenciesV1{Sessions: f.q.f.s.HTMLCreationSessions, Audit: f.q.f.s.Audit, PublicURL: f.q.f.s.PublicURL}, f.q.f.s.NoticeAccess, actor, f.original.ID, f.record.ID, in, "192.0.2.1", "")
	if out != nil {
		defer out.CloseConsumerV1()
	}
	if err != nil || out == nil {
		t.Fatal("actual native notice did not produce a retained result", err)
	}
	before := f.q.snapshotV1(t)
	pending := f.q.runtime.SessionsV1().PendingV1()
	if before.Global.ParentBytes <= baseline.Global.ParentBytes || before.Global.DBStagingBytes <= baseline.Global.DBStagingBytes || pending.WorkSessions != 0 || pending.HTMLAdmissions == 0 {
		t.Fatal("notice result was not genuinely retained after actual physical SQL retirement", before, pending)
	}
	raw, err := json.Marshal(out)
	var issued amendments.OutcomeV1
	if err != nil || json.Unmarshal(raw, &issued) != nil || issued.State != "committed" || issued.Notice == nil || len(issued.Notice.Deliveries) != 1 {
		t.Fatal("actual retained serializer lost complete notice output", err)
	}
	if f.q.snapshotV1(t) != before {
		t.Fatal("serialization alone prematurely refunded still-owned result buffers")
	}
	out.CloseConsumerV1()
	if after := f.q.snapshotV1(t); after != baseline {
		t.Fatal("actual final result Close did not reconcile its same retired native admission", before, after, baseline)
	}
	request, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationE2E(f.q.f.s, http.MethodPost, "/api/v1/documents/"+f.original.ID.String()+"/amendments/"+f.record.ID.String()+"/notice", string(request), f.q.cookie)
	var replay amendments.OutcomeV1
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &replay) != nil || replay.State != "unchanged" || replay.Notice == nil || replay.Notice.ID != issued.Notice.ID {
		t.Fatal("immediate exact HTTP replay required an external cleanup sweep or repeated issuance", response.Code, response.Body.String())
	}
	var notices, deliveries, accesses, events int
	err = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT
 (SELECT count(*) FROM document_amendment_notices_v1 WHERE amendment_id=$1),
 (SELECT count(*) FROM document_amendment_notice_deliveries_v1 WHERE notice_id=$2),
 (SELECT count(*) FROM document_amendment_notice_access_v1 WHERE notice_id=$2),
 (SELECT count(*) FROM events WHERE document_id=$3 AND kind='document.amendment_notice_queued' AND payload_json->>'notice_id'=$4)`, f.record.ID, issued.Notice.ID, f.original.ID, issued.Notice.ID.String()).Scan(&notices, &deliveries, &accesses, &events) //nolint:rawsql -- actual exact replay has one immutable set of effects
	if err != nil || notices != 1 || deliveries != 1 || accesses != 1 || events != 1 {
		t.Fatal("last-use cleanup changed actual idempotency/effects", notices, deliveries, accesses, events, err)
	}
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("cleanup/replay changed original completed evidence")
	}
	f.q.assertObserversOnlyV1(t)
}
