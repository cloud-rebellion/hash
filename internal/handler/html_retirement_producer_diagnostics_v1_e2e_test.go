//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Fresh full-collection numeric evidence supplements the unchanged complete
// journey. These controlled synthetic-admin reads neither repair caches nor
// grant runtime work; no payload, credential or private diagnostic is logged.
func TestOwnedHTMLRetirementFreshProducerDiagnosticsE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	original, parties := q.createSentV1(t)
	fields, err := q.f.q.ListFieldsByDocument(q.f.ctx, original.ID)
	if err != nil || len(fields) != 2 {
		t.Fatal("actual original managed fields absent", err)
	}
	oldFieldIDs := map[string]bool{}
	for _, field := range fields {
		oldFieldIDs[field.ID.String()] = true
	}
	bootstrap := q.requestV1(parties[0].Token, "")
	var page signerContextResponse
	if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil || page.DocumentID != original.ID || page.Privacy.NoticeDigest == "" || page.PDFObservation == nil {
		t.Fatal("genuine public context/notice unavailable")
	}
	var beforeOwnerMail int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1", q.f.user.Email).Scan(&beforeOwnerMail); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- exact synthetic owner outbox witness only
	requestBody, err := json.Marshal(signerRequestChangesInput{Message: "Please revise the declared service scope", Proposed: "Human-approved revised synthetic service scope"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/sign/"+parties[0].Token+"/request-changes", bytes.NewReader(requestBody)).WithContext(q.f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", q.f.s.PublicURL)
	request.Header.Set(signerNoticeDigestHeader, page.Privacy.NoticeDigest)
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, request)
	var changed map[string]string
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &changed) != nil || changed["status"] != "changes_requested" {
		t.Fatalf("genuine notice-bound public change request=%d %s", response.Code, response.Body.String())
	}
	var afterOwnerMail, noticeEvents int
	var noticeBound bool
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE to_email=$1", q.f.user.Email).Scan(&afterOwnerMail); err != nil || afterOwnerMail != beforeOwnerMail+1 {
		t.Fatal("actual negotiation owner notification not enqueued exactly once", err)
	} //nolint:rawsql -- actual queueing, not SMTP delivery claim
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer,coalesce(bool_and(payload_json->>$4=$5),false) FROM events WHERE org_id=$1 AND document_id=$2 AND recipient_id=$3 AND kind='document.changes_requested'", q.f.org, original.ID, parties[0].RecipientID, article13.AuditNoticeDigestKey, page.Privacy.NoticeDigest).Scan(&noticeEvents, &noticeBound); err != nil || noticeEvents != 1 || !noticeBound {
		t.Fatal("actual change response did not bind original server notice", err)
	} //nolint:rawsql -- exact fresh response evidence oracle
	ownedRevisionConsumedV1(t, q)
	requests, err := q.f.q.ListChangeRequests(q.f.ctx, original.ID)
	if err != nil || len(requests) != 1 {
		t.Fatal("actual change request missing", err)
	}
	base := "/api/v1/documents/" + original.ID.String()
	if w := submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/change-requests/"+requests[0].ID.String()+"/approve", "", q.cookie); w.Code != http.StatusOK {
		t.Fatalf("genuine sender approval=%d %s", w.Code, w.Body.String())
	}
	paused, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: q.f.org})
	if err != nil || paused.Status != "changes_requested" || !sameSignerDocumentSource(original, paused) {
		t.Fatal("HTML approval auto-applied unreviewed prose or lost paused state", err)
	}
	h, err := q.f.q.GetHTMLRevisionSnapshotSizeHeaderV1(q.f.ctx, generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: original.ID, OrgID: q.f.org})
	if err != nil || h == nil {
		t.Fatal("actual collection diagnostic header unavailable")
	}
	t.Logf("actual retirement header fields=%d measured_fields=%d events=%d measured_events=%d histories=%d measured_histories=%d scope_mismatches=%d server=%d", h.FieldCount, h.MeasuredFieldCount, h.EventCount, h.MeasuredEventCount, h.HistoryCount, h.MeasuredHistoryCount, h.EventScopeMismatchCount, h.ServerVersionNum)
	if h.FieldCount != h.MeasuredFieldCount || h.EventCount != h.MeasuredEventCount || h.HistoryCount != h.MeasuredHistoryCount || h.EventScopeMismatchCount != 0 || h.ServerVersionNum != 160015 {
		t.Error("genuine fresh producers did not measure the complete original retirement collections")
	}
	if w := submitSessionOperationE2E(q.f.s, http.MethodPost, base+"/revise", "", q.cookie); w.Code != http.StatusOK {
		t.Fatalf("actual retirement after numeric header=%d", w.Code)
	}
	q.assertObserversOnlyV1(t)
}
